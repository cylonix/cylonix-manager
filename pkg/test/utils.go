package test

import "fmt"

func ErrNotImplemented(method string) error {
	return fmt.Errorf("method %v is not implemented", method)
}
