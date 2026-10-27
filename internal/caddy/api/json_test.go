package api

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDecodeJSON_DepthLimit(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 100) + `"x"` + strings.Repeat("}", 100)
	req, _ := http.NewRequest("POST", "/", strings.NewReader(deep))
	var v map[string]interface{}
	err := DecodeJSON(req, &v, 64)
	if err == nil {
		t.Fatal("expected error for deep JSON")
	}
	if !errors.Is(err, ErrJSONDepthExceeded) {
		t.Errorf("expected ErrJSONDepthExceeded, got: %v", err)
	}
}

func TestDecodeJSON_Valid(t *testing.T) {
	body := `{"domain":"example.com","ttl":3600}`
	req, _ := http.NewRequest("POST", "/", strings.NewReader(body))
	var v struct {
		Domain string `json:"domain"`
		TTL    int    `json:"ttl"`
	}
	err := DecodeJSON(req, &v, 64)
	if err != nil {
		t.Fatal(err)
	}
	if v.Domain != "example.com" || v.TTL != 3600 {
		t.Errorf("got domain=%q ttl=%d", v.Domain, v.TTL)
	}
}

func TestDecodeJSON_EmptyBody(t *testing.T) {
	req, _ := http.NewRequest("POST", "/", strings.NewReader(""))
	req.Body = io.NopCloser(strings.NewReader(""))
	var v map[string]interface{}
	err := DecodeJSON(req, &v, 64)
	if err == nil {
		t.Fatal("expected error for empty body")
	}
}
