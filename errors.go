package middleware

import (
	"fmt"
	"net/http"
)

type AuthError struct {
	Message string `json:"message,omitempty"`
	Status  int    `json:"status"`
	Title   string `json:"title"`
}

func (err AuthError) Error() string {
	return err.Message
}

func AuthorizationMissingError() *AuthError {
	return &AuthError{
		Message: "Authorization header is missing",
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}

func BearTokenError() *AuthError {
	return &AuthError{
		Message: "Bearer token is missing or improperly formatted",
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}

func NotAuthorizedError(roles []string) *AuthError {
	return &AuthError{
		Message: fmt.Sprintf("Client is not assigned any roles allowed for this resource (%s)", roles),
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}

func ScopeMissingError(scope string) *AuthError {
	return &AuthError{
		Message: fmt.Sprintf("Bearer token does not contain requested scope (%s)", scope),
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}

func TokenParseError(m string) *AuthError {
	return &AuthError{
		Message: m,
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}

func TokenValidationError(m string) *AuthError {
	return &AuthError{
		Message: m,
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}
