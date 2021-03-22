package middleware

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/o1egl/paseto"
)

var bearerRE = regexp.MustCompile(`(?i)Bearer `)

type TokenHandler struct {
	publicKeyMap map[paseto.Version]crypto.PublicKey
	symmetricKey []byte
}

func NewTokenHandler(keys ...interface{}) TokenHandler {
	var symmetricKey []byte
	keyMap := map[paseto.Version]crypto.PublicKey{}

	for _, key := range keys {
		switch key := key.(type) {
		case ed25519.PublicKey:
			keyMap[paseto.Version2] = key
		case rsa.PublicKey:
			keyMap[paseto.Version1] = key
		case []byte:
			symmetricKey = key
		case string:
			symmetricKey = []byte(key)
		}
	}

	return TokenHandler{
		publicKeyMap: keyMap,
		symmetricKey: symmetricKey,
	}
}

// ScopeAuthorization provides gin middleware to validate both the scope is as expected and that
// the token has not expired
func (th TokenHandler) ScopeAuthorization(allowedScopes ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		jwt, err := th.readAuthorization(ctx)
		if err != nil {
			ctx.Error(err)
			ctx.Abort()
			return
		}

		// get scopes granted to token
		assignedScopes := jwt.Get("scope")

		// see if any allowed roles are assigned
		allowed := false
		for _, scope := range allowedScopes {
			if strings.Contains(assignedScopes, scope) {
				allowed = true
				break
			}
		}

		// return with error when not allowed
		if !allowed {
			ctx.Error(NotAuthorizedError(allowedScopes))
			ctx.Abort()
			return
		}
	}
}

func (th TokenHandler) ValidToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if _, err := th.readAuthorization(ctx); err != nil {
			ctx.Error(err)
			ctx.Abort()
			return
		}
	}
}

func (th TokenHandler) parse(pst string, token *paseto.JSONToken) error {
	var footer string

	if _, err := paseto.Parse(pst, &token, &footer, th.symmetricKey, th.publicKeyMap); err != nil {
		return err
	}

	return nil
}

func (th TokenHandler) readAuthorization(ctx *gin.Context) (paseto.JSONToken, error) {
	var jwt paseto.JSONToken
	auth := ctx.GetHeader("Authorization")

	// ensure a valid auth header
	if auth == "" {
		return jwt, AuthorizationMissingError()
	}

	// ensure we have a bearer token
	if !bearerRE.MatchString(auth) {
		return jwt, BearTokenError()
	}

	// isolate the bearer token (in format "Bearer v2.local.XXXXXXXXX...")
	pst := bearerRE.Split(auth, -1)[1]

	// attempt to extract the token
	if err := th.parse(pst, &jwt); err != nil {
		return jwt, TokenParseError(err.Error())
	}

	// validate the date
	if err := jwt.Validate(); err != nil {
		return jwt, TokenValidationError(err.Error())
	}

	return jwt, nil
}
