package middleware

import (
	"fmt"
	"net/http"
	"strings"
)

// AuthError contains details regarding any authorization errors
// encountered while attempting to read or parse a PASETO token
type AuthError struct {
	Message string `json:"message,omitempty"`
	Status  int    `json:"status"`
	Title   string `json:"title"`
}

// Error provides details about the error
func (err AuthError) Error() string {
	return err.Message
}

// AuthorizationMissingError is for when the Authorization header
// is not present in the request
func AuthorizationMissingError() *AuthError {
	return &AuthError{
		Message: "Authorization header is missing",
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}

// BearerTokenError is for when the Authorization header is not
// properly formatted or does not contain an actual Bearer value
func BearTokenError() *AuthError {
	return &AuthError{
		Message: "Bearer token is missing or improperly formatted",
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}

// NotAuthorizedError is for when the provided PASETO token is not
// allowed access due to a scope validation failure
func NotAuthorizedError(scopes []string) *AuthError {
	return &AuthError{
		Message: fmt.Sprintf(
			"Token is not granted a scope that is allowed for this resource (%s)",
			strings.Join(scopes, ", ")),
		Status: http.StatusUnauthorized,
		Title:  "Unauthorized",
	}
}

// TokenParseError is for when the PASETO token can't be parsed properly
func TokenParseError(m string) *AuthError {
	return &AuthError{
		Message: m,
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}

// TokenValidationError occurs when the PASETO token is
// expired or invalid and no scopes are being checked
func TokenValidationError(m string) *AuthError {
	return &AuthError{
		Message: m,
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}
