# PASETO Token Middleware

Middleware designed for use within [gin-gonic/gin](https://github.com/gin-gonic/gin) microservices to validate PASETO Bearer tokens.

## Usage

```go
package main

import (
  middleware "github.com/clearchanneloutdoor/token-middleware"
	"github.com/gin-gonic/gin"
)

func main() {
  ge := gin.Default()

  // setup a v2 private key
  symmetricKey := "brozeph, where is my secret key?" // 32 bytes
  
  // setup a v2 public key
  b, _ := hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
  publicKey := ed25519.PublicKey(b)

  // create a token handler for v2 private and public paseto tokens
  th := middleware.NewTokenHandler([]byte(symmetricKey), publicKey)

  // validate with a specified claim
  ge.GET("/foos", th.ScopeAuthorization("foos", "read", "modify"), func (ctx *gin.Context) {
    // middleware will check the token to see if there is a claim with a dictionary key named 
    // "foos" with a value of either "read" or "modify"
    ctx.IndentedJSON(http.StatusOK, gin.H{
      "foos": "yeah!"
    })
  })

  // validate for non-expired PASETO only (no claims required)
  ge.GET("/bars", th.ValidToken(), func (ctx *gin.Context) {
    // middleware will check to see if the PASETO token has not expired, but 
    // will not perform any other validations
    ctx.IndentedJSON(http.StatusOK, gin.H{
      "bars": "woot!"
    })
  })

  ge.Run(":8080")
}
```