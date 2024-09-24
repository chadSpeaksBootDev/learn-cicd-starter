package main

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestAuth(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "no authorisation header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "missing api header",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "missing api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid authorisation header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			expectedKey: "abc123",
			expectedErr: nil,
		},
	}

	for _, i := range tests {
		t.Run(i.name, func(t *testing.T) {
			key, err := auth.GetAPIKey(i.headers)
			if key != i.expectedKey {
				t.Errorf("Expected key %s; got %s", i.expectedKey, key)
			}
			if i.name == "valid authorisation header" {
				if err != nil {
					t.Errorf("Expected error %v; got %v", i.expectedErr, err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error %v; got %v", i.expectedErr, err)
				}
			}
		})
	}
}
