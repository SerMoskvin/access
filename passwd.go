package access

import "golang.org/x/crypto/bcrypt"

type PasswordHasher struct {
	cost int
	auth *Authenticator
}

func NewPasswordHasher(cost int, auth *Authenticator) *PasswordHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &PasswordHasher{
		cost: cost,
		auth: auth,
	}
}

func (p *PasswordHasher) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	return string(bytes), err
}

func (p *PasswordHasher) CheckPasswordHash(password, hash string) bool {
	cacheKey := hash + ":" + password
	if result, ok := p.auth.passwordCache.Get(cacheKey); ok {
		return result.(bool)
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	result := err == nil
	p.auth.passwordCache.Set(cacheKey, result)
	return result
}
