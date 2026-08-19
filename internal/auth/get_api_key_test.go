package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		wantErr     error
		wantErrText string // used when we only expect an error type/message, not a sentinel
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey abc123"}},
			wantKey: "abc123",
			wantErr: nil,
		},
		{
			name:    "missing authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed header - missing key",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:     "",
			wantErrText: "malformed authorization header",
		},
		{
			name:        "malformed header - wrong scheme",
			headers:     http.Header{"Authorization": []string{"Bearer abc123"}},
			wantKey:     "",
			wantErrText: "malformed authorization header",
		},
		{
			name:    "malformed header - empty string",
			headers: http.Header{"Authorization": []string{""}},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "extra whitespace-separated segments still works",
			headers: http.Header{"Authorization": []string{"ApiKey abc123 extra"}},
			wantKey: "abc123",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if got != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", got, tt.wantKey)
			}

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}
			case tt.wantErrText != "":
				if err == nil || err.Error() != tt.wantErrText {
					t.Errorf("GetAPIKey() error = %v, want error text %q", err, tt.wantErrText)
				}
			default:
				if err != nil {
					t.Errorf("GetAPIKey() unexpected error = %v", err)
				}
			}
		})
	}
}
