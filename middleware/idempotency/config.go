package idempotency

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/internal/storage/memory"
)

var (
	ErrInvalidIdempotencyKey = errors.New("invalid idempotency key")
)

// Config defines the config for middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	//
	// Optional. Default: a function which skips the middleware on safe HTTP request method.
	Next func(c fiber.Ctx) bool

	// Lifetime is the maximum lifetime of an idempotency key.
	//
	// Optional. Default: 30 * time.Minute
	Lifetime time.Duration

	// KeyHeader is the name of the header that contains the idempotency key.
	//
	// Optional. Default: X-Idempotency-Key
	KeyHeader string
	// KeyHeaderValidate defines a function to validate the syntax of the idempotency header.
	//
	// Optional. Default: a function which ensures the header is 36 characters long (the size of an UUID).
	KeyHeaderValidate func(string) error

	// KeepResponseHeaders is a list of headers that should be kept from the original response.
	//
	// Optional. Default: nil (to keep all headers)
	KeepResponseHeaders []string

	// Lock locks an idempotency key.
	//
	// Optional. Default: an in-memory locker for this process only.
	Lock Locker
	// Storage stores response data by idempotency key.
	//
	// Optional. Default: an in-memory storage for this process only.
	Storage fiber.Storage

	// MarshalFunc is the function used to marshal a Response to a []byte.
	//
	// Optional. Default: a marshal function which uses "encoding/gob" from the Go standard library.
	MarshalFunc func(*Response) ([]byte, error)
	// UnmarshalFunc is the function used to unmarshal a []byte back to a Response.
	//
	// Optional. Default: an unmarshal function which uses "encoding/gob" from the Go standard library.
	UnmarshalFunc func([]byte, *Response) error
}

// ConfigDefault is the default config
var ConfigDefault = Config{
	Next: func(c fiber.Ctx) bool {
		// Skip middleware if the request was done using a safe HTTP method
		return fiber.IsMethodSafe(c.Method())
	},

	Lifetime: 30 * time.Minute,

	KeyHeader: "X-Idempotency-Key",
	KeyHeaderValidate: func(k string) error {
		if l, wl := len(k), 36; l != wl { // UUID length is 36 chars
			return fmt.Errorf("%w: invalid length: %d != %d", ErrInvalidIdempotencyKey, l, wl)
		}

		return nil
	},

	KeepResponseHeaders: nil,

	Lock: NewMemoryLock(),
	Storage: memory.New(memory.Config{
		GCInterval: 15 * time.Minute, // Half the key lifetime
	}),

	MarshalFunc: func(res *Response) ([]byte, error) {
		var buf bytes.Buffer
		if err := gob.
			NewEncoder(&buf).
			Encode(res); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	},
	UnmarshalFunc: func(val []byte, res *Response) error {
		if err := gob.
			NewDecoder(bytes.NewReader(val)).
			Decode(res); err != nil {
			return err
		}
		return nil
	},
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	// Return default config if nothing provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	// Set default values

	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
	}

	if cfg.Lifetime.Nanoseconds() == 0 {
		cfg.Lifetime = ConfigDefault.Lifetime
	}

	if cfg.KeyHeader == "" {
		cfg.KeyHeader = ConfigDefault.KeyHeader
	}
	if cfg.KeyHeaderValidate == nil {
		cfg.KeyHeaderValidate = ConfigDefault.KeyHeaderValidate
	}

	if cfg.KeepResponseHeaders != nil && len(cfg.KeepResponseHeaders) == 0 {
		cfg.KeepResponseHeaders = ConfigDefault.KeepResponseHeaders
	}

	if cfg.Lock == nil {
		cfg.Lock = ConfigDefault.Lock
	}
	if cfg.Storage == nil {
		cfg.Storage = ConfigDefault.Storage
	}

	if cfg.MarshalFunc == nil {
		cfg.MarshalFunc = ConfigDefault.MarshalFunc
	}
	if cfg.UnmarshalFunc == nil {
		cfg.UnmarshalFunc = ConfigDefault.UnmarshalFunc
	}

	return cfg
}
