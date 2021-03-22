package middleware

import (
	"fmt"
	"net/http"
	"strings"
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

func NotAuthorizedError(scopes []string) *AuthError {
	return &AuthError{
		Message: fmt.Sprintf(
			"Token is not granted a scope that is allowed for this resource (%s)",
			strings.Join(scopes, ", ")),
		Status: http.StatusUnauthorized,
		Title:  "Unauthorized",
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
