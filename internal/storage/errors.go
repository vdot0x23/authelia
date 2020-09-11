package storage

import "errors"

var (
	// ErrNoU2FDeviceHandle error thrown when no U2F device handle has been found in DB.
	ErrNoU2FDeviceHandle = errors.New("No U2F device handle found")

	// ErrNoTOTPSecret error thrown when no TOTP secret has been found in DB.
	ErrNoTOTPSecret = errors.New("No TOTP secret registered")
)
