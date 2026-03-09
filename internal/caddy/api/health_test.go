package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name       string
		dbCheck    func(context.Context) error
		wantStatus int
		wantBody   string
	}{
		{
			name:       "healthy when db ok",
			dbCheck:    func(ctx context.Context) error { return nil },
			wantStatus: http.StatusOK,
			wantBody:   `"status":"ok"`,
		},
		{
			name:       "degraded when db fails",
			dbCheck:    func(ctx context.Context) error { return context.DeadlineExceeded },
			wantStatus: http.StatusOK,
			wantBody:   `"status":"degraded"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHealthHandler(tt.dbCheck)
			req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if !strings.Contains(w.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want to contain %q", w.Body.String(), tt.wantBody)
			}
		})
	}
}
