package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// ErrJSONDepthExceeded is returned when JSON nesting exceeds the limit.
var ErrJSONDepthExceeded = errors.New("JSON nesting depth exceeded")

const defaultMaxJSONDepth = 64

// DecodeJSON reads and decodes JSON from r with depth and size limits to prevent DoS.
func DecodeJSON(r *http.Request, v interface{}, maxDepth int) error {
	if maxDepth <= 0 {
		maxDepth = defaultMaxJSONDepth
	}
	if r.Body == nil {
		return errors.New("request body is empty")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return errors.New("request body is empty")
	}
	if err := checkJSONDepth(body, maxDepth); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// checkJSONDepth verifies that JSON nesting does not exceed maxDepth.
func checkJSONDepth(data []byte, maxDepth int) error {
	depth := 0
	i := 0
	for i < len(data) {
		c := data[i]
		switch c {
		case '"':
			i++
			for i < len(data) {
				if data[i] == '\\' {
					i += 2
					continue
				}
				if data[i] == '"' {
					i++
					break
				}
				i++
			}
		case '{', '[':
			depth++
			if depth > maxDepth {
				return ErrJSONDepthExceeded
			}
			i++
		case '}', ']':
			depth--
			i++
		default:
			i++
		}
	}
	return nil
}
