// Package middleware provides handlers for PASETO token verification
// and authorization for gin-gonic/gin API servers
package middleware

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"regexp"
	"strings"

	pasetov4 "aidanwoods.dev/go-paseto"
	"github.com/gin-gonic/gin"
	legacyPaseto "github.com/o1egl/paseto"
)

var bearerRE = regexp.MustCompile(`(?i)Bearer `)

// TokenHandler provides middleware for validating and reading the
// details from a PASETO token provided as a bearer token on the
// request
type TokenHandler struct {
	publicKeyMap map[legacyPaseto.Version]crypto.PublicKey
	symmetricKey []byte
}

// NewTokenHandler creates a new middleware handler with the specified keys
// for properly verifying or decrypting v1, v2, and v4 PASETO tokens provided
// as bearer tokens within the Authorization header of a request
func NewTokenHandler(keys ...interface{}) TokenHandler {
	var symmetricKey []byte
	keyMap := map[legacyPaseto.Version]crypto.PublicKey{}

	for _, key := range keys {
		switch key := key.(type) {
		case ed25519.PublicKey:
			keyMap[legacyPaseto.Version2] = key
		case rsa.PublicKey:
			keyMap[legacyPaseto.Version1] = key
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
		jwt, err := th.readJWT(ctx)
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

// ValidToken provides gin middleware that ensures a bearer token in the
// request has valid and has not expired.
func (th TokenHandler) ValidToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if _, err := th.readJWT(ctx); err != nil {
			ctx.Error(err)
			ctx.Abort()
			return
		}
	}
}

func isV4Local(token string) bool {
	return strings.HasPrefix(token, "v4.local.")
}

func (th TokenHandler) parseV4Local(pst string, token *legacyPaseto.JSONToken) error {
	key, err := pasetov4.V4SymmetricKeyFromBytes(th.symmetricKey)
	if err != nil {
		return err
	}

	// skip the library's built-in expiry check so jwt.Validate() handles it
	// consistently with the v2 path, giving callers a uniform TokenValidationError
	tok, err := pasetov4.NewParserWithoutExpiryCheck().ParseV4Local(key, pst, nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(tok.ClaimsJSON(), token)
}

func (th TokenHandler) parse(pst string, token *legacyPaseto.JSONToken) error {
	if isV4Local(pst) {
		return th.parseV4Local(pst, token)
	}

	var footer string
	if _, err := legacyPaseto.Parse(pst, token, &footer, th.symmetricKey, th.publicKeyMap); err != nil {
		return err
	}

	return nil
}

func (th TokenHandler) readJWT(ctx *gin.Context) (legacyPaseto.JSONToken, error) {
	var jwt legacyPaseto.JSONToken

	// look for the jwt in the context of Gin
	if t, exists := ctx.Get("jwt"); exists {
		return t.(legacyPaseto.JSONToken), nil
	}

	// look for bearer token in the query
	pst := ctx.Query("bearer_token")

	// if paseto is not in query, check for a valid auth header
	if pst == "" {
		auth := ctx.GetHeader("Authorization")

		if auth == "" {
			return jwt, AuthorizationMissingError()
		}

		// ensure we have a bearer token
		if !bearerRE.MatchString(auth) {
			return jwt, BearerTokenError()
		}

		// isolate the bearer token (in format "Bearer v2.local.XXXXXXXXX...")
		pst = bearerRE.Split(auth, -1)[1]
	}

	// attempt to extract the token
	if err := th.parse(pst, &jwt); err != nil {
		return jwt, TokenParseError(err.Error())
	}

	// validate the date
	if err := jwt.Validate(); err != nil {
		return jwt, TokenValidationError(err.Error())
	}

	// set the paseto and decrypted token on the context for subsequent use
	ctx.Set("pst", pst)
	ctx.Set("jwt", jwt)
	ctx.Set("jti", jwt.Jti)

	return jwt, nil
}
