package main

import (
	"errors"
	"fmt"
	"git.ronaksoft.com/river/msg/go/msg"
)

var (
	ErrHandlerNotSet       = errors.New("handlers are not set")
	ErrRequestTimeout      = errors.New("request timeout")
	ErrInvalidConstructor  = errors.New("constructor did not expected")
	ErrSecretNonceMismatch = errors.New("secret hash does not match")
	ErrAuthFailed          = errors.New("creating auth key failed")
	ErrNoConnection        = errors.New("no connection")
	ErrNotFound            = errors.New("not found")
	ErrDoesNotExists       = errors.New("does not exists")
	ErrQueuePathIsNotSet   = errors.New("queue path is not set")
)

// ServerError
func ServerError(b []byte) error {
	x := new(msg.Error)
	x.Unmarshal(b)
	return errors.New(fmt.Sprintf("%s:%s", x.Code, x.Items))
}
