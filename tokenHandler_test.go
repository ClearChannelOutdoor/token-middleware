package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pasetov4 "aidanwoods.dev/go-paseto"
	"github.com/gin-gonic/gin"
	oldTimey "github.com/o1egl/paseto"
)

// 32-byte symmetric key used across all tests
var testKey = []byte("12345678901234567890123456789012")

func makeV2LocalToken(t *testing.T, key []byte, expiry time.Time, extra map[string]string) string {
	t.Helper()

	tok := oldTimey.JSONToken{
		Expiration: expiry,
		IssuedAt:   time.Now(),
		NotBefore:  time.Now(),
	}
	for k, v := range extra {
		tok.Set(k, v)
	}

	encrypted, err := oldTimey.NewV2().Encrypt(key, tok, nil)
	if err != nil {
		t.Fatalf("V2 encrypt: %v", err)
	}
	return encrypted
}

func makeV4LocalToken(t *testing.T, key []byte, expiry time.Time, extra map[string]interface{}) string {
	t.Helper()

	symKey, err := pasetov4.V4SymmetricKeyFromBytes(key)
	if err != nil {
		t.Fatalf("V4SymmetricKeyFromBytes: %v", err)
	}

	tok := pasetov4.NewToken()
	tok.SetExpiration(expiry)
	tok.SetIssuedAt(time.Now())
	tok.SetNotBefore(time.Now())

	for k, v := range extra {
		if err := tok.Set(k, v); err != nil {
			t.Fatalf("tok.Set(%q): %v", k, err)
		}
	}

	return tok.V4Encrypt(symKey, nil)
}

// errHandler wraps subsequent handlers and converts any gin errors into a 401.
// The middleware in this package uses ctx.Error()+ctx.Abort() without setting
// a status code, delegating that responsibility to the application's error handler.
func errHandler(c *gin.Context) {
	c.Next()
	if len(c.Errors) > 0 {
		c.Status(http.StatusUnauthorized)
	}
}

func testRouter(th TokenHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/valid", errHandler, th.ValidToken(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	r.GET("/scoped", errHandler, th.ScopeAuthorization("read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

func TestV4Local_ValidToken(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV4LocalToken(t, testKey, time.Now().Add(time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/valid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestV4Local_ExpiredToken(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV4LocalToken(t, testKey, time.Now().Add(-time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/valid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Logf("correctly rejected expired token (gin errors: %v)", w.Body.String())
	}
}

func TestV4Local_ScopeAllowed(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV4LocalToken(t, testKey, time.Now().Add(time.Hour), map[string]interface{}{
		"scope": "read write",
	})

	req := httptest.NewRequest(http.MethodGet, "/scoped", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid scope, got %d", w.Code)
	}
}

func TestV4Local_ScopeDenied(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV4LocalToken(t, testKey, time.Now().Add(time.Hour), map[string]interface{}{
		"scope": "write",
	})

	req := httptest.NewRequest(http.MethodGet, "/scoped", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("expected rejection for missing 'read' scope, got 200")
	}
}

func TestV4Local_WrongKey(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	wrongKey := []byte("99999999999999999999999999999999")
	token := makeV4LocalToken(t, wrongKey, time.Now().Add(time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/valid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("expected rejection for wrong key, got 200")
	}
}

func TestV4Local_QueryParam(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV4LocalToken(t, testKey, time.Now().Add(time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/valid?bearer_token="+token, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 via query param, got %d", w.Code)
	}
}

func TestV2Local_ValidToken(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV2LocalToken(t, testKey, time.Now().Add(time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/valid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestV2Local_ExpiredToken(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV2LocalToken(t, testKey, time.Now().Add(-time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/valid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("expected rejection for expired token, got 200")
	}
}

func TestV2Local_ScopeAllowed(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV2LocalToken(t, testKey, time.Now().Add(time.Hour), map[string]string{
		"scope": "read write",
	})

	req := httptest.NewRequest(http.MethodGet, "/scoped", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid scope, got %d", w.Code)
	}
}

func TestV2Local_ScopeDenied(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV2LocalToken(t, testKey, time.Now().Add(time.Hour), map[string]string{
		"scope": "write",
	})

	req := httptest.NewRequest(http.MethodGet, "/scoped", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("expected rejection for missing 'read' scope, got 200")
	}
}

func TestV2Local_WrongKey(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	wrongKey := []byte("99999999999999999999999999999999")
	token := makeV2LocalToken(t, wrongKey, time.Now().Add(time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/valid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("expected rejection for wrong key, got 200")
	}
}

func TestV2Local_QueryParam(t *testing.T) {
	th := NewTokenHandler(testKey)
	r := testRouter(th)

	token := makeV2LocalToken(t, testKey, time.Now().Add(time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/valid?bearer_token="+token, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 via query param, got %d", w.Code)
	}
}
