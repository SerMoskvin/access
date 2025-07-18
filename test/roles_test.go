package access_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/SerMoskvin/access"
)

func TestPermissionsConfig(t *testing.T) {
	testConfig := &access.PermissionsConfig{
		Roles: map[string]access.RolePermissions{
			"admin": {
				Role: "admin",
				Sections: []access.Section{
					{Name: "Users", URL: "/users", CanRead: true, CanWrite: true},
				},
				OwnRecordsOnly: false,
			},
			"teacher": {
				Role: "teacher",
				Sections: []access.Section{
					{Name: "Grades", URL: "/grades", CanRead: true, CanWrite: true},
				},
				OwnRecordsOnly: true,
			},
			"student": {
				Role: "student",
				Sections: []access.Section{
					{Name: "Grades", URL: "/grades", CanRead: true, CanWrite: false},
				},
				OwnRecordsOnly: true,
			},
		},
	}

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
			perms, ok := testConfig.Roles[tt.role]
			if !ok {
				t.Fatalf("Role %s not found in PermissionsConfig", tt.role)
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
