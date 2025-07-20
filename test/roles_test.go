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
					{
						Name:     "Users",
						URL:      "/users",
						CanRead:  true,
						CanWrite: true,
					},
				},
				OwnRecordsOnly: false,
			},
			"teacher": {
				Role: "teacher",
				Sections: []access.Section{
					{
						Name:     "Grades",
						URL:      "/grades",
						CanRead:  true,
						CanWrite: true,
					},
				},
				OwnRecordsOnly: true,
			},
			"student": {
				Role: "student",
				Sections: []access.Section{
					{
						Name:     "Grades",
						URL:      "/grades",
						CanRead:  true,
						CanWrite: false,
					},
				},
				OwnRecordsOnly: true,
			},
		},
	}

	tests := []struct {
		name       string
		role       string
		path       string
		method     string
		shouldPass bool
	}{
		{
			name:       "Admin can GET /users",
			role:       "admin",
			path:       "/users",
			method:     http.MethodGet,
			shouldPass: true,
		},
		{
			name:       "Admin can POST /users",
			role:       "admin",
			path:       "/users",
			method:     http.MethodPost,
			shouldPass: true,
		},
		{
			name:       "Teacher can POST /grades",
			role:       "teacher",
			path:       "/grades",
			method:     http.MethodPost,
			shouldPass: true,
		},
		{
			name:       "Teacher cannot GET /users",
			role:       "teacher",
			path:       "/users",
			method:     http.MethodGet,
			shouldPass: false,
		},
		{
			name:       "Student can GET /grades",
			role:       "student",
			path:       "/grades",
			method:     http.MethodGet,
			shouldPass: true,
		},
		{
			name:       "Student cannot POST /grades",
			role:       "student",
			path:       "/grades",
			method:     http.MethodPost,
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
					if (tt.method == http.MethodPost ||
						tt.method == http.MethodPut ||
						tt.method == http.MethodDelete) && section.CanWrite {
						hasAccess = true
						break
					}
				}
			}

			if hasAccess != tt.shouldPass {
				t.Errorf(
					"Access mismatch for %s: %s %s (expected %v, got %v)",
					tt.role,
					tt.method,
					tt.path,
					tt.shouldPass,
					hasAccess,
				)
			}
		})
	}
}
