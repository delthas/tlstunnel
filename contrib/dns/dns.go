package dns

import (
	"errors"
)

func getParams(params []string, values ...*string) error {
	if len(params) < len(values) {
		return errors.New("not enough parameters")
	}
	for i, v := range values {
		*v = params[i]
	}
	return nil
}
