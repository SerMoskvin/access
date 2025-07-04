package access

// Роли пользователей
const (
	RoleAdmin    = "admin"
	RoleTeacher  = "teacher"
	RoleStudent  = "student"
	RoleEmployee = "employee"
)

// Откуда куда перенаправлять по ролям
var RoleRedirects = map[string]string{
	RoleAdmin:    "/admin/dashboard",
	RoleTeacher:  "/teacher/dashboard",
	RoleStudent:  "/student/dashboard",
	RoleEmployee: "/employee/dashboard",
}

// Получить URL для перенаправления по роли
func RedirectURL(role string) string {
	url, ok := RoleRedirects[role]
	if !ok {
		return "/" // главная страница
	}
	return url
}
