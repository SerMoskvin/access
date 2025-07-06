package access

type RolePermissions struct {
	Role           string
	Sections       []Section
	OwnRecordsOnly bool
}

type Section struct {
	Name     string
	URL      string
	CanRead  bool
	CanWrite bool
}

func CheckRecordAccess(userID int, userRole string, ownerID int) bool {
	rolePerms, ok := permissionsMap[userRole]
	if !ok {
		return false
	}

	// Если у роли есть OwnRecordsOnly и пользователь не является владельцем
	if rolePerms.OwnRecordsOnly && userID != ownerID {
		return false
	}

	return true
}
