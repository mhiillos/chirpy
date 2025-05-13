package auth

import(
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "mypassword"
	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatal("Error: %w", err)
	}
	err = CheckPasswordHash(hashed, password)
	if err != nil {
		t.Fatalf("Password %q does not match hash %q", password, hashed)
	}
	wrongPassword := "wrongpassword"
	err = CheckPasswordHash(hashed, wrongPassword)
	if err == nil {
		t.Fatalf("Password %q should not match hash %q", wrongPassword, hashed)
	}
}
