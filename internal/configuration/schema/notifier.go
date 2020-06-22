package schema

// FileSystemNotifierConfiguration represents the configuration of the notifier writing emails in a file.
type FileSystemNotifierConfiguration struct {
	Filename string `mapstructure:"filename"`
}

// SMTPNotifierConfiguration represents the configuration of the SMTP server to send emails with.
type SMTPNotifierConfiguration struct {
	Host                string `mapstructure:"host"`
	Port                int    `mapstructure:"port"`
	Username            string `mapstructure:"username"`
	Password            string `mapstructure:"password"`
	Sender              string `mapstructure:"sender"`
	Subject             string `mapstructure:"subject"`
	TrustedCert         string `mapstructure:"trusted_cert"`
	SecretSigningKey    string `mapstructure:"secret_signing_key"`
	StartupCheckAddress string `mapstructure:"startup_check_address"`
	DisableVerifyCert   bool   `mapstructure:"disable_verify_cert"`
	DisableRequireTLS   bool   `mapstructure:"disable_require_tls"`
}

// NotifierConfiguration represents the configuration of the notifier to use when sending notifications to users.
type NotifierConfiguration struct {
	DisableStartupCheck bool                             `mapstructure:"disable_startup_check"`
	FileSystem          *FileSystemNotifierConfiguration `mapstructure:"filesystem"`
	SMTP                *SMTPNotifierConfiguration       `mapstructure:"smtp"`
}

// DefaultSMTPNotifierConfiguration represents default configuration parameters for the SMTP notifier.
var DefaultSMTPNotifierConfiguration = SMTPNotifierConfiguration{
	Subject: "[Authelia] {title}",
}
