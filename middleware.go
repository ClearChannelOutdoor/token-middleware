package middleware

import "github.com/gin-gonic/gin"

type tokenHandler struct {
	privateKey string
	publicKey  string
}

func (th tokenHandler) ScopeAuthorization(scope string, roles ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		auth := ctx.GetHeader("Authorization")

		if auth == "" {
			ctx.Error(AuthorizationMissingError("Authorization header is missing"))
			ctx.Abort()
			return
		}
	}
}
