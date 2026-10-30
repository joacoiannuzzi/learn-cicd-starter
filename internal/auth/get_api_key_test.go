package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		setAuth bool
		wantKey string
		wantErr error
		errAny  bool
	}{
		{
			name:    "valid api key",
			header:  "ApiKey abc123",
			setAuth: true,
			wantKey: "abc123",
		},
		{
			name:    "no authorization header",
			setAuth: false,
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty authorization header",
			header:  "",
			setAuth: true,
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "missing key after scheme",
			header:  "ApiKey",
			setAuth: true,
			errAny:  true,
		},
		{
			name:    "wrong scheme",
			header:  "Bearer abc123",
			setAuth: true,
			errAny:  true,
		},
		{
			name:    "lowercase scheme",
			header:  "apikey abc123",
			setAuth: true,
			errAny:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.setAuth {
				headers.Set("Authorization", tt.header)
			}

			gotKey, err := GetAPIKey(headers)

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			case tt.errAny:
				if err == nil {
					t.Fatalf("expected error, got nil (key %q)", gotKey)
				}
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if gotKey != tt.wantKey {
					t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
				}
			}
		})
	}
}
