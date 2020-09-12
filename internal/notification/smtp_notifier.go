package notification

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	//"net/mail"
	"net/smtp"
	"strings"
	"time"
	"os"

	_ "github.com/emersion/go-message/charset"
	//"github.com/emersion/go-message"
	//msgmail "github.com/emersion/go-message/mail"
	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	//"github.com/emersion/go-pgpmail"
	"github.com/authelia/authelia/internal/configuration/schema"
	"github.com/authelia/authelia/internal/utils"
)

// SMTPNotifier a notifier to send emails to SMTP servers.
type SMTPNotifier struct {
	username            string
	password            string
	sender              string
	host                string
	port                int
	trustedCert         string
	disableVerifyCert   bool
	disableRequireTLS   bool
	address             string
	subject             string
	startupCheckAddress string
	client              *smtp.Client
	tlsConfig           *tls.Config
	secretSigningKey    *openpgp.Entity
}


// NewSMTPNotifier creates a SMTPNotifier using the notifier configuration.
func NewSMTPNotifier(configuration schema.SMTPNotifierConfiguration) (*SMTPNotifier, error) {
	notifier := &SMTPNotifier{
		username:            configuration.Username,
		password:            configuration.Password,
		sender:              configuration.Sender,
		host:                configuration.Host,
		port:                configuration.Port,
		trustedCert:         configuration.TrustedCert,
		disableVerifyCert:   configuration.DisableVerifyCert,
		disableRequireTLS:   configuration.DisableRequireTLS,
		address:             fmt.Sprintf("%s:%d", configuration.Host, configuration.Port),
		subject:             configuration.Subject,
		startupCheckAddress: configuration.StartupCheckAddress,
	}

	loadKeyfile := func(path string) (*openpgp.Entity, error) {
		if path == "" {
			log.Debug("No secret signing key provided, so emails will not be signed")
			return nil, nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		entity, err := openpgp.ReadEntity(packet.NewReader(f))
		if err != nil {
			return nil, err
		}
		return entity, nil
	}

	var err error
	notifier.secretSigningKey, err = loadKeyfile(configuration.SecretSigningKey)
	if err != nil {
		return nil, err
	}
	notifier.initializeTLSConfig()

	return notifier, nil
}

func (n *SMTPNotifier) initializeTLSConfig() {
	// Do not allow users to disable verification of certs if they have also set a trusted cert that was loaded
	// The second part of this check happens in the Configure Cert Pool code block
	log.Debug("Notifier SMTP client initializing TLS configuration")

	//Configure Cert Pool
	certPool, err := x509.SystemCertPool()
	if err != nil || certPool == nil {
		certPool = x509.NewCertPool()
	}

	if n.trustedCert != "" {
		log.Debugf("Notifier SMTP client attempting to load certificate from %s", n.trustedCert)

		if exists, err := utils.FileExists(n.trustedCert); exists {
			pem, err := ioutil.ReadFile(n.trustedCert)
			if err != nil {
				log.Warnf("Notifier SMTP failed to load cert from file with error: %s", err)
			} else {
				if ok := certPool.AppendCertsFromPEM(pem); !ok {
					log.Warn("Notifier SMTP failed to import cert loaded from file")
				} else {
					log.Debug("Notifier SMTP successfully loaded certificate")
					if n.disableVerifyCert {
						log.Warn("Notifier SMTP when trusted_cert is specified we force disable_verify_cert to false, if you want to disable certificate validation please comment/delete trusted_cert from your config")
						n.disableVerifyCert = false
					}
				}
			}
		} else {
			log.Warnf("Notifier SMTP failed to load cert from file (file does not exist) with error: %s", err)
		}
	}

	n.tlsConfig = &tls.Config{
		InsecureSkipVerify: n.disableVerifyCert, //nolint:gosec // This is an intended config, we never default true, provide alternate options, and we constantly warn the user.
		ServerName:         n.host,
		RootCAs:            certPool,
	}
}

// Do startTLS if available (some servers only provide the auth extension after, and encryption is preferred).
func (n *SMTPNotifier) startTLS() error {
	// Only start if not already encrypted
	if _, ok := n.client.TLSConnectionState(); ok {
		log.Debugf("Notifier SMTP connection is already encrypted, skipping STARTTLS")
		return nil
	}

	switch ok, _ := n.client.Extension("STARTTLS"); ok {
	case true:
		log.Debugf("Notifier SMTP server supports STARTTLS (disableVerifyCert: %t, ServerName: %s), attempting", n.tlsConfig.InsecureSkipVerify, n.tlsConfig.ServerName)

		if err := n.client.StartTLS(n.tlsConfig); err != nil {
			return err
		}

		log.Debug("Notifier SMTP STARTTLS completed without error")
	default:
		switch n.disableRequireTLS {
		case true:
			log.Warn("Notifier SMTP server does not support STARTTLS and SMTP configuration is set to disable the TLS requirement (only useful for unauthenticated emails over plain text)")
		default:
			return errors.New("Notifier SMTP server does not support TLS and it is required by default (see documentation if you want to disable this highly recommended requirement)")
		}
	}

	return nil
}

// Attempt Authentication.
func (n *SMTPNotifier) auth() error {
	// Attempt AUTH if password is specified only.
	if n.password != "" {
		_, ok := n.client.TLSConnectionState()
		if !ok {
			return errors.New("Notifier SMTP client does not support authentication over plain text and the connection is currently plain text")
		}

		// Check the server supports AUTH, and get the mechanisms.
		ok, m := n.client.Extension("AUTH")
		if ok {
			var auth smtp.Auth

			log.Debugf("Notifier SMTP server supports authentication with the following mechanisms: %s", m)
			mechanisms := strings.Split(m, " ")

			// Adaptively select the AUTH mechanism to use based on what the server advertised.
			if utils.IsStringInSlice("PLAIN", mechanisms) {
				auth = smtp.PlainAuth("", n.username, n.password, n.host)

				log.Debug("Notifier SMTP client attempting AUTH PLAIN with server")
			} else if utils.IsStringInSlice("LOGIN", mechanisms) {
				auth = newLoginAuth(n.username, n.password, n.host)

				log.Debug("Notifier SMTP client attempting AUTH LOGIN with server")
			}

			// Throw error since AUTH extension is not supported.
			if auth == nil {
				return fmt.Errorf("notifier SMTP server does not advertise a AUTH mechanism that are supported by Authelia (PLAIN or LOGIN are supported, but server advertised %s mechanisms)", m)
			}

			// Authenticate.
			if err := n.client.Auth(auth); err != nil {
				return err
			}

			log.Debug("Notifier SMTP client authenticated successfully with the server")

			return nil
		}

		return errors.New("Notifier SMTP server does not advertise the AUTH extension but config requires AUTH (password specified), either disable AUTH, or use an SMTP host that supports AUTH PLAIN or AUTH LOGIN")
	}

	log.Debug("Notifier SMTP config has no password specified so authentication is being skipped")

	return nil
}

func (n *SMTPNotifier) compose(recipient, subject, body, htmlBody string) error {
	log.Debugf("Notifier SMTP client attempting to send email body to %s", recipient)

	if !n.disableRequireTLS {
		_, ok := n.client.TLSConnectionState()
		if !ok {
			return errors.New("Notifier SMTP client can't send an email over plain text connection")
		}
	}

	wc, err := n.client.Data()
	if err != nil {
		log.Debugf("Notifier SMTP client error while obtaining WriteCloser: %s", err)
		return err
	}
	if n.secretSigningKey == nil {
		boundary := utils.RandomString(30, utils.AlphaNumericCharacters)

		now := time.Now()

		msg := "Date:" + now.Format(rfc5322DateTimeLayout) + "\r\n" +
			"From: " + n.sender + "\r\n" +
			"To: " + recipient + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-version: 1.0\r\n" +
			"Content-Type: multipart/alternative; boundary=" + boundary + "\r\n\n" +
			"--" + boundary + "\r\n" +
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
			"Content-Transfer-Encoding: quoted-printable\r\n" +
			"Content-Disposition: inline\r\n\n" +
			body + "\r\n"

		if htmlBody != "" {
			msg += "--" + boundary + "\r\n" +
				"Content-Type: text/html; charset=\"UTF-8\"\r\n\n" +
				htmlBody + "\r\n"
		}

		msg += "--" + boundary + "--" + "\r\n"

		_, err = fmt.Fprint(wc, msg)
		if err != nil {
			log.Debugf("Notifier SMTP client error while sending email body over WriteCloser: %s", err)
			return err
		}
	} else {
		outerBoundary := utils.RandomString(30, utils.AlphaNumericCharacters)
		boundary := utils.RandomString(30, utils.AlphaNumericCharacters)

		now := time.Now()

		pre := "Date:" + now.Format(rfc5322DateTimeLayout) + "\r\n" +
			"From: " + n.sender + "\r\n" +
			"To: " + recipient + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-version: 1.0\r\n" +
			"Content-Type: multipart/signed; micalg=pgp-sha256; protocol=\"application/pgp\"; boundary=" + outerBoundary + "\r\n\r\n" +
			"--" + outerBoundary + "\r\n"

		msg :="Content-Type: multipart/alternative; boundary=" + boundary + "\r\n" +
			"Content-Transfer-Encoding: 7bit" + "\r\n\r\n" +
			"--" + boundary + "\r\n" +
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
			"Content-Transfer-Encoding: quoted-printable\r\n" +
			"Content-Disposition: inline\r\n\r\n" +
			body + "\r\n"

		if htmlBody != "" {
			msg += "--" + boundary + "\r\n" +
				"Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n" +
				htmlBody + "\r\n"
		}
		msg += "--" + boundary + "--" + "\r\n"

		var sig strings.Builder
		err := openpgp.ArmoredDetachSignText(&sig, n.secretSigningKey, strings.NewReader(msg), nil)
		if err != nil {
			return err
		}
		signed := pre + msg
		signed += "--" + outerBoundary + "\r\n" +
			"Content-Type: application/pgp-signature; name=\"signature.asc\"" + "\r\n" +
			"Content-Disposition: attachment; filename=\"signature.asc\"" + "\r\n" +
			"Content-Description: OpenPGP digital signature" + "\r\n\r\n"
		signed += sig.String() + "\r\n\r\n" + "--" + outerBoundary + "--"

		_, err = fmt.Fprint(wc, signed)
		if err != nil {
			log.Debugf("Notifier SMTP client error while sending email body over WriteCloser: %s", err)
			return err
		}

		/*
		from, err := mail.ParseAddress(n.sender)
		if err != nil {
			return err
		}

		to, err := mail.ParseAddress(recipient)
		if err != nil {
			return err
		}

		var htmlHeader msgmail.Header
		htmlHeader.SetContentType("text/html", nil)
		html, err := message.New(htmlHeader.Header, strings.NewReader(htmlBody))
		if err != nil {
			return err
		}

		var plainHeader msgmail.Header
		plainHeader.SetContentType("text/plain", nil)
		plain, err := message.New(plainHeader.Header, strings.NewReader(body))
		if err != nil {
			return err
		}

		var rootHeader msgmail.Header
		rootHeader.SetAddressList("From", []*msgmail.Address{{from.Name, from.Address}})
		rootHeader.SetAddressList("To", []*msgmail.Address{{to.Name, to.Address}})

		var msg *strings.Builder
		html.WriteTo(msg)
		plain.WriteTo(msg)

		//msg, err := message.NewMultipart(rootHeader.Header, []*message.Entity{html, plain})


		var signedHeader message.Header
		signedHeader.SetContentType("multipart/signed", nil)

		wcSigned, err := pgpmail.Sign(wc, rootHeader.Header.Header, signedHeader.Header, n.secretSigningKey, nil)
		if err != nil {
			return err
		}

		_, err = fmt.Fprint(wcSigned, msg.String())
		if err != nil {
			return err
		}

		if err := wcSigned.Close(); err != nil {
			return err
		}
		*/
	}

	err = wc.Close()
	if err != nil {
		log.Debugf("Notifier SMTP client error while closing the WriteCloser: %s", err)
		return err
	}

	return nil
}

// Dial the SMTP server with the SMTPNotifier config.
func (n *SMTPNotifier) dial() error {
	log.Debugf("Notifier SMTP client attempting connection to %s", n.address)

	if n.port == 465 {
		log.Warnf("Notifier SMTP client configured to connect to a SMTPS server. It's highly recommended you use a non SMTPS port and STARTTLS instead of SMTPS, as the protocol is long deprecated.")

		conn, err := tls.Dial("tcp", n.address, n.tlsConfig)
		if err != nil {
			return err
		}

		client, err := smtp.NewClient(conn, n.host)
		if err != nil {
			return err
		}

		n.client = client
	} else {
		client, err := smtp.Dial(n.address)
		if err != nil {
			return err
		}

		n.client = client
	}

	log.Debug("Notifier SMTP client connected successfully")

	return nil
}

// Closes the connection properly.
func (n *SMTPNotifier) cleanup() {
	err := n.client.Quit()
	if err != nil {
		log.Warnf("Notifier SMTP client encountered error during cleanup: %s", err)
	}
}

// StartupCheck checks the server is functioning correctly and the configuration is correct.
func (n *SMTPNotifier) StartupCheck() (bool, error) {
	if err := n.dial(); err != nil {
		return false, err
	}

	defer n.cleanup()

	if err := n.startTLS(); err != nil {
		return false, err
	}

	if err := n.auth(); err != nil {
		return false, err
	}

	if err := n.client.Mail(n.sender); err != nil {
		return false, err
	}

	if err := n.client.Rcpt(n.startupCheckAddress); err != nil {
		return false, err
	}

	if err := n.client.Reset(); err != nil {
		return false, err
	}

	return true, nil
}

// Send is used to send an email to a recipient.
func (n *SMTPNotifier) Send(recipient, title, body, htmlBody string) error {
	subject := strings.ReplaceAll(n.subject, "{title}", title)

	if err := n.dial(); err != nil {
		return err
	}

	// Always execute QUIT at the end once we're connected.
	defer n.cleanup()

	// Start TLS and then Authenticate.
	if err := n.startTLS(); err != nil {
		return err
	}

	if err := n.auth(); err != nil {
		return err
	}

	// Set the sender and recipient first.
	if err := n.client.Mail(n.sender); err != nil {
		log.Debugf("Notifier SMTP failed while sending MAIL FROM (using sender) with error: %s", err)
		return err
	}

	if err := n.client.Rcpt(recipient); err != nil {
		log.Debugf("Notifier SMTP failed while sending RCPT TO (using recipient) with error: %s", err)
		return err
	}

	// Compose and send the email body to the server.
	if err := n.compose(recipient, subject, body, htmlBody); err != nil {
		return err
	}

	log.Debug("Notifier SMTP client successfully sent email")

	return nil
}
