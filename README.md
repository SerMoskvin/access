Package "Access" provides authentication and authorization of users in the system and transmits the URL depending on the user's role Example of "roles.go":

const ( RoleAdmin = "admin" RoleEmployee = "employee" )

// route table var RoleRedirects = map[string]string{ RoleAdmin: "/admin/dashboard", RoleEmployee: "/employee/dashboard", }

// Get URL func RedirectURL(role string) string { url, ok := RoleRedirects[role] if !ok { return "/" // главная страница } return url }
