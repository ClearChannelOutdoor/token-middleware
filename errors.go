package middleware

import "net/http"

type AuthError struct {
	Message string `json:"message,omitempty"`
	Status  int    `json:"status"`
	Title   string `json:"title"`
}

func (err AuthError) Error() string {
	return err.Message
}

func AuthorizationMissingError(m string) *AuthError {
	return &AuthError{
		Message: m,
		Status:  http.StatusUnauthorized,
		Title:   "Unauthorized",
	}
}
