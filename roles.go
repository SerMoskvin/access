package access

var PermissionsMap = map[string]RolePermissions{
	"admin": {
		Role: "admin",
		Sections: []Section{
			{Name: "Расписание", URL: "/schedule", CanRead: true, CanWrite: true},
			{Name: "Занятия", URL: "/lessons", CanRead: true, CanWrite: true},
			{Name: "Сотрудники", URL: "/employee", CanRead: true, CanWrite: true},
			{Name: "Аудитория", URL: "/audience", CanRead: true, CanWrite: true},
			{Name: "Инструмент", URL: "/instruments", CanRead: true, CanWrite: true},
			{Name: "Пользователь", URL: "/users", CanRead: true, CanWrite: true},
			{Name: "Ученики", URL: "/students", CanRead: true, CanWrite: true},
			{Name: "Группы", URL: "/groups", CanRead: true, CanWrite: true},
			{Name: "Оценки", URL: "/grades", CanRead: true, CanWrite: true},
			{Name: "Посещение", URL: "/attendance", CanRead: true, CanWrite: true},
			{Name: "Программа", URL: "/programs", CanRead: true, CanWrite: true},
		},
		OwnRecordsOnly: false,
	},
	"teacher": {
		Role: "teacher",
		Sections: []Section{
			{Name: "Оценки", URL: "/grades", CanRead: true, CanWrite: true},
			{Name: "Посещение", URL: "/attendance", CanRead: true, CanWrite: true},
		},
		OwnRecordsOnly: true,
	},
	"student": {
		Role: "student",
		Sections: []Section{
			{Name: "Оценки", URL: "/grades", CanRead: true, CanWrite: false},
			{Name: "Посещение", URL: "/attendance", CanRead: true, CanWrite: false},
			{Name: "Инструмент", URL: "/instruments", CanRead: true, CanWrite: false},
		},
		OwnRecordsOnly: true,
	},
	"employee": {
		Role: "employee",
		Sections: []Section{
			{Name: "Аудитория", URL: "/audience", CanRead: true, CanWrite: true},
			{Name: "Инструмент", URL: "/instruments", CanRead: true, CanWrite: true},
		},
		OwnRecordsOnly: false,
	},
}
