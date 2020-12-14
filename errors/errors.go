package _errors

import (
	"errors"
)

var (
	ErrHandlerNotSet       = errors.New("handlers are not set")
	ErrRequestTimeout      = errors.New("request timeout")
	ErrInvalidConstructor  = errors.New("constructor did not expected")
	ErrSecretNonceMismatch = errors.New("secret hash does not match")
	ErrAuthFailed          = errors.New("creating auth key failed")
	ErrNoAuthKey        = errors.New("no auth key")
	ErrNotFound            = errors.New("not found")
)
