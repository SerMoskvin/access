package access

import "golang.org/x/crypto/bcrypt"

type PasswordHasher struct {
	cost int
}

func NewPasswordHasher(cost int) *PasswordHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &PasswordHasher{cost: cost}
}

func (p *PasswordHasher) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	return string(bytes), err
}

func (p *PasswordHasher) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
