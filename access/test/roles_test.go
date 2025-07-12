package access_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/SerMoskvin/access"
)

func TestPermissionsMap(t *testing.T) {
	tests := []struct {
		role       string
		path       string
		method     string
		shouldPass bool
	}{
		{"admin", "/users", http.MethodGet, true},
		{"admin", "/users", http.MethodPost, true},
		{"teacher", "/grades", http.MethodPost, true},
		{"teacher", "/users", http.MethodGet, false},
		{"student", "/grades", http.MethodGet, true},
		{"student", "/grades", http.MethodPost, false},
	}

	for _, tt := range tests {
		t.Run(tt.role+"_"+tt.method+"_"+tt.path, func(t *testing.T) {
			perms, ok := access.PermissionsMap[tt.role]
			if !ok {
				t.Fatalf("Role %s not found in PermissionsMap", tt.role)
			}

			var hasAccess bool
			for _, section := range perms.Sections {
				if strings.HasPrefix(tt.path, section.URL) {
					if tt.method == http.MethodGet && section.CanRead {
						hasAccess = true
						break
					}
					if (tt.method == http.MethodPost || tt.method == http.MethodPut || tt.method == http.MethodDelete) && section.CanWrite {
						hasAccess = true
						break
					}
				}
			}

			if hasAccess != tt.shouldPass {
				t.Errorf("Expected access %v, got %v for %s %s", tt.shouldPass, hasAccess, tt.method, tt.path)
			}
		})
	}
}
