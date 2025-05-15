package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "mysecretstring"

	tokenString, err := MakeJWT(userID, tokenSecret, 1*time.Second)
	if err != nil {
		t.Fatalf("Error creating JWT: %s", err)
	}

	// Valid JWT, IDs should match
	validatedID, err := ValidateJWT(tokenString, tokenSecret)
	if err != nil {
		t.Fatalf("Error validating JWT: %s", err)
	}
	if userID != validatedID {
		t.Fatalf("Validation failed: %s != %s", userID, validatedID)
	}

	// Wrong secret, should not pass validation
	_, err = ValidateJWT(tokenString, "wrongsecret")
	expectedErr := errors.New("token signature is invalid: signature is invalid")
	if err == nil {
		t.Fatalf("Expected error: %v, but got nil", expectedErr.Error())
	} else if !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Fatalf("Expected error message: %v, but got: %v", expectedErr.Error(), err.Error())
	}

	// Expired JWT, should not pass validation
	shortExpiryToken, err := MakeJWT(userID, tokenSecret, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Error creating JWT with short expiry: %s", err)
	}

	_, err = ValidateJWT(shortExpiryToken, tokenSecret)
	expectedErr = errors.New("token has invalid claims: token is expired")
	if err == nil {
		t.Fatalf("Expected error: %v, but got nil", expectedErr.Error())
	} else if !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Fatalf("Expected error message: %v, but got: %v", expectedErr.Error(), err.Error())
	}
}
