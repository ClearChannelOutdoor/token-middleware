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
  ge.GET("/foos", th.ScopeAuthorization("cool-scope", "another-scope", "yet-another-scope"), func (ctx *gin.Context) {
    // middleware will check the token to see if there is a scope that matches any of the
    // allowed scopes supplied to the ScopeAuthorization function
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

### TokenHandler

The token handler middleware can be initialized with public and/or symmetric keys in order to validate and extract JWT details from PASETO tokens that are provided as Bearer tokens on API requests. 

If the API only requires handling of `v2` PASETO local tokens, the token handler can be initialized with a single 32 byte symmetric key (a `string` or `[]byte` value). If `v2` public, `v2` local and `v1` public keys all require validation, then the token handler can be created with an Ed25519 public key, a 32 byte symmetric key (`string` or `[]byte`) and an RSA public key.

For example, the following creates a v2 private PASETO token parser

```go
symmetricKey := "brozeph, where is my secret key?" // 32 bytes
handler := middleware.NewTokenHandler(symmetricKey)
```

The following is a reference to the PASETO specification protocol versions and encryption / signing details:

 | local | public
v1| AES-256-CTR + HMAC-SHA384 | 2048-bit RSA public key
v2| XChaCha20-Poly1305 | Ed25519

The PASETO bearer tokens are expected to be provided via the inbound request in the `Authorization` header:

```http
GET /v1/things/1234 HTTP/1.1
Authorization: Bearer v2.private.HkM8o... // <- PASETO token
```

#### Middleware

Once the `TokenHandler` has been created, it can be used to register middleware on a per API endpoint or resource basis.

Take, for example, the API resource below... ``GET` requests to `/v1/things` is being handled by a function called `GetThings`. 

```go
func RegisterAPIResources(c *gin.Engine, bs interfaces.IThingsController) {
  c.GET("/v1/things", bs.GetThings)
}
```

In order to secure the `GET` request to `/v1/things`, a `TokenHandler`, like the one created earlier, can perform the authorization in middleware with a minor tweak to the above method:

```go
func RegisterAPIResources(c *gin.Engine, th *middleware.TokenHandler, bs interfaces.IThingsController) {
  c.GET("/v1/things", th.ScopeAuthorization("things-read"), bs.GetThings)
}
```

The middleware now looks for a valid (non-expired, properly formatted and parseable) PASETO token containing the scope `things-read`. In the event there is a problem, the middleware will register the error in the `*gin.Context` and abort the request. Otherwise, the request will succeed and the `GetThings` method will be called to handle the request.

##### Errors

The middleware will register errors of type `AuthError`. The `AuthError` contains 3 fields:

* `Message` - a string message specific to the error
* `Status` - an Int representing the HTTP status for unauthorized (401)
* `Title` - a string value for the type of error, "Unauthorized"

The following is an example middleware error reporter that can be used to properly output the error and status to the request when there is an authorization problem.

```go
func errorReporter(ctx *gin.Context) {
  ctx.Next()
  detectedErrs := ctx.Errors.ByType(gin.ErrorTypeAny)

  if len(detectedErrs) == 0 {
    return
  }

  // handle the last error
  err := detectedErrs.Last().Err
  switch err := err.(type) {
  case *middleware.AuthError:
    ctx.IndentedJSON(err.Status, err)
    ctx.Abort()
  case *myerrors.MyError:
    // handle custom errors
  default:
    // do some other processing here...
  }
}
```

##### JSON Token

The data stored in the PASETO is a JSON Token. This token contains scopes and claims that may be useful for subsequent API route handling, so the unencrypted JSON Token data is added to the `*gin.Context` per request.

```go
func (c APIController) GetThings(ctx *gin.Context) {
  // the middleware has already authorized this request...
  // retrieve the token...
  jwt := ctx.Get("jwt")(paseto.JSONToken)

  // pull a custom claim from the token 
  // if it is expected to be there...
  thingOwner, err := jwt.Get("thingOwner")
  if err != nil {
    ctx.Error(errors.New("where's mah claim?!?!"))
    return
  }

  // do some stuff with the thingOwner...
}
```
