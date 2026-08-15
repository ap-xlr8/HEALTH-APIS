package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/security"
)

type fakeIdentityStore struct {
	usersByEmail  map[string]models.User
	usersByID     map[string]models.User
	sessions      map[string]models.Session
	createUserErr error
	sessionErr    error
	deleteErr     error
}

func newFakeIdentityStore() *fakeIdentityStore {
	return &fakeIdentityStore{
		usersByEmail: map[string]models.User{},
		usersByID:    map[string]models.User{},
		sessions:     map[string]models.Session{},
	}
}

func (f *fakeIdentityStore) CreateUser(ctx context.Context, user models.User) error {
	if f.createUserErr != nil {
		return f.createUserErr
	}
	f.usersByEmail[user.Email] = user
	f.usersByID[user.ID] = user
	return nil
}

func (f *fakeIdentityStore) FindUserByEmail(ctx context.Context, email string) (models.User, error) {
	user, ok := f.usersByEmail[email]
	if !ok {
		return models.User{}, store.ErrNotFound
	}
	return user, nil
}

func (f *fakeIdentityStore) FindUserByID(ctx context.Context, id string) (models.User, error) {
	user, ok := f.usersByID[id]
	if !ok {
		return models.User{}, store.ErrNotFound
	}
	return user, nil
}

func (f *fakeIdentityStore) FindUserByVerificationToken(ctx context.Context, token string) (models.User, error) {
	for _, u := range f.usersByID {
		if u.VerificationToken == token {
			return u, nil
		}
	}
	return models.User{}, store.ErrNotFound
}

func (f *fakeIdentityStore) VerifyUserEmail(ctx context.Context, token string) (models.User, error) {
	for id, u := range f.usersByID {
		if u.VerificationToken == token {
			u.EmailVerified = true
			u.VerificationToken = ""
			u.VerificationExpiresAt = nil
			f.usersByID[id] = u
			f.usersByEmail[u.Email] = u
			return u, nil
		}
	}
	return models.User{}, store.ErrNotFound
}

func (f *fakeIdentityStore) UpdateUserFailedLogins(ctx context.Context, userID string, attempts int, lockoutUntil *time.Time) error {
	if u, ok := f.usersByID[userID]; ok {
		u.FailedLoginAttempts = attempts
		u.LockoutUntil = lockoutUntil
		f.usersByID[userID] = u
		f.usersByEmail[u.Email] = u
	}
	return nil
}

func (f *fakeIdentityStore) ResetUserFailedLogins(ctx context.Context, userID string) error {
	if u, ok := f.usersByID[userID]; ok {
		u.FailedLoginAttempts = 0
		u.LockoutUntil = nil
		f.usersByID[userID] = u
		f.usersByEmail[u.Email] = u
	}
	return nil
}

func (f *fakeIdentityStore) CreateSession(ctx context.Context, session models.Session) error {
	if f.sessionErr != nil {
		return f.sessionErr
	}
	f.sessions[session.ID] = session
	return nil
}

func (f *fakeIdentityStore) FindSessionByID(ctx context.Context, id string) (models.Session, error) {
	session, ok := f.sessions[id]
	if !ok {
		return models.Session{}, store.ErrNotFound
	}
	return session, nil
}

func (f *fakeIdentityStore) DeleteSessionByID(ctx context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.sessions, id)
	return nil
}

func (f *fakeIdentityStore) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	for id, s := range f.sessions {
		if s.UserID == userID {
			delete(f.sessions, id)
		}
	}
	return nil
}

func TestValidateRegister(t *testing.T) {
	t.Parallel()
	valid := registerRequest{
		Email:     "juan@example.com",
		Password:  "Secure!1234",
		Role:      "patient",
		FirstName: "Juan",
		LastName:  "Perez",
	}
	if err := validateRegister(valid); err != nil {
		t.Fatalf("expected valid registration, got %v", err)
	}

	invalid := valid
	invalid.Role = "admin"
	if err := validateRegister(invalid); err == nil {
		t.Fatal("expected role validation error")
	}

	invalid = valid
	invalid.Password = "insecure"
	if err := validateRegister(invalid); err == nil {
		t.Fatal("expected password validation error")
	}

	invalid = valid
	invalid.Email = "not-email"
	if err := validateRegister(invalid); err == nil {
		t.Fatal("expected email validation error")
	}

	invalid = valid
	invalid.FirstName = ""
	if err := validateRegister(invalid); err == nil {
		t.Fatal("expected name validation error")
	}
}

func TestRegisterVerifyAndLogin(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	fakeStore := newFakeIdentityStore()
	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	registerReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{
		"email":"juan@example.com",
		"password":"Secure!1234",
		"role":"patient",
		"first_name":"Juan",
		"last_name":"Perez"
	}`))
	registerRes := httptest.NewRecorder()
	handler.Register(registerRes, registerReq)
	if registerRes.Code != http.StatusCreated {
		t.Fatalf("expected register 201, got %d body=%s", registerRes.Code, registerRes.Body.String())
	}

	savedUser, ok := fakeStore.usersByEmail["juan@example.com"]
	if !ok || savedUser.VerificationToken == "" {
		t.Fatalf("expected saved user with verification token in store")
	}
	verificationToken := savedUser.VerificationToken

	// Login before verifying must fail with 403 Forbidden
	unverifiedLogin := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"juan@example.com","password":"Secure!1234"}`))
	unverifiedRes := httptest.NewRecorder()
	handler.LoginMobile(unverifiedRes, unverifiedLogin)
	if unverifiedRes.Code != http.StatusForbidden {
		t.Fatalf("expected unverified login 403, got %d body=%s", unverifiedRes.Code, unverifiedRes.Body.String())
	}

	// Verify email
	verifyReq := httptest.NewRequest(http.MethodPost, "/v1/auth/verify-email", strings.NewReader(`{"token":"`+verificationToken+`"}`))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRes := httptest.NewRecorder()
	handler.VerifyEmail(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusOK {
		t.Fatalf("expected verify email 200, got %d body=%s", verifyRes.Code, verifyRes.Body.String())
	}

	// Login after verify must succeed
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"juan@example.com","password":"Secure!1234"}`))
	loginRes := httptest.NewRecorder()
	handler.LoginMobile(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d body=%s", loginRes.Code, loginRes.Body.String())
	}
	var loginPayload struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(loginRes.Body.Bytes(), &loginPayload); err != nil {
		t.Fatalf("login json: %v", err)
	}
	if loginPayload.RefreshToken == "" || len(fakeStore.sessions) != 1 {
		t.Fatalf("expected refresh token and session, sessions=%d", len(fakeStore.sessions))
	}

	refreshReq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+loginPayload.RefreshToken+`"}`))
	refreshRes := httptest.NewRecorder()
	handler.Refresh(refreshRes, refreshReq)
	if refreshRes.Code != http.StatusOK {
		t.Fatalf("expected refresh 200, got %d body=%s", refreshRes.Code, refreshRes.Body.String())
	}
	if len(fakeStore.sessions) != 1 {
		t.Fatalf("expected refresh rotation to keep exactly one active session, got %d", len(fakeStore.sessions))
	}
}

func TestRefreshRejectsExpiredSession(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	fakeStore := newFakeIdentityStore()
	user := models.User{ID: "usr_1", Email: "juan@example.com", Role: models.RolePatient, EmailVerified: true}
	fakeStore.usersByID[user.ID] = user
	token, jti, err := signRefreshForTest(privateKey, user.ID, user.Role)
	if err != nil {
		t.Fatalf("signRefreshForTest: %v", err)
	}
	fakeStore.sessions[jti] = models.Session{ID: jti, UserID: user.ID, Kind: "refresh", ExpiresAt: time.Now().UTC().Add(-time.Minute)}
	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+token+`"}`))
	res := httptest.NewRecorder()

	handler.Refresh(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", res.Code, res.Body.String())
	}
}

func TestLoginWebSetsSecureCookies(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	fakeStore := newFakeIdentityStore()
	user := models.User{
		ID:            "usr_doc",
		Email:         "doc@example.com",
		PasswordHash:  "",
		Role:          "caregiver",
		EmailVerified: true,
	}
	user.PasswordHash, _ = security.HashPassword("Doctor!123")
	fakeStore.usersByID[user.ID] = user
	fakeStore.usersByEmail[user.Email] = user

	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/web/login", strings.NewReader(`{"email":"doc@example.com","password":"Doctor!123"}`))
	res := httptest.NewRecorder()
	handler.LoginWeb(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	cookies := res.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("expected secure cookies, got %d", len(cookies))
	}
	for _, cookie := range cookies {
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("cookie is not hardened: %#v", cookie)
		}
	}
}

func TestRegisterRejectsInvalidPayload(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	handler := New(newFakeIdentityStore(), privateKey, &privateKey.PublicKey, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{"email":"bad"}`))
	res := httptest.NewRecorder()

	handler.Register(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Code)
	}

	badJSON := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{`))
	badJSONRes := httptest.NewRecorder()
	handler.Register(badJSONRes, badJSON)
	if badJSONRes.Code != http.StatusBadRequest {
		t.Fatalf("expected bad json 400, got %d", badJSONRes.Code)
	}
}

func TestLoginRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	handler := New(newFakeIdentityStore(), privateKey, &privateKey.PublicKey, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"missing@example.com","password":"Secure!1234"}`))
	res := httptest.NewRecorder()

	handler.LoginMobile(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}

	badJSON := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{`))
	badJSONRes := httptest.NewRecorder()
	handler.LoginMobile(badJSONRes, badJSON)
	if badJSONRes.Code != http.StatusBadRequest {
		t.Fatalf("expected bad json 400, got %d", badJSONRes.Code)
	}
}

func TestLoginRejectsWrongPasswordAndLocksAccount(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	fakeStore := newFakeIdentityStore()
	user := models.User{
		ID:            "usr_1",
		Email:         "juan@example.com",
		Role:          models.RolePatient,
		EmailVerified: true,
	}
	user.PasswordHash, _ = security.HashPassword("Secure!1234")
	fakeStore.usersByID[user.ID] = user
	fakeStore.usersByEmail[user.Email] = user

	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"juan@example.com","password":"Wrong!1234"}`))
		res := httptest.NewRecorder()
		handler.LoginMobile(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, res.Code)
		}
	}

	// 5th failed attempt triggers lockout
	req5 := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"juan@example.com","password":"Wrong!1234"}`))
	res5 := httptest.NewRecorder()
	handler.LoginMobile(res5, req5)
	if res5.Code != http.StatusUnauthorized {
		t.Fatalf("5th attempt: expected 401, got %d", res5.Code)
	}

	// 6th attempt should be blocked with 429
	req6 := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"juan@example.com","password":"Secure!1234"}`))
	res6 := httptest.NewRecorder()
	handler.LoginMobile(res6, req6)
	if res6.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 account locked, got %d body=%s", res6.Code, res6.Body.String())
	}
}

func TestRefreshRejectsInvalidJSONAndToken(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	handler := New(newFakeIdentityStore(), privateKey, &privateKey.PublicKey, nil)
	for _, body := range []string{`{`, `{"refresh_token":"bad"}`} {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
		res := httptest.NewRecorder()
		handler.Refresh(res, req)
		if res.Code != http.StatusBadRequest && res.Code != http.StatusUnauthorized {
			t.Fatalf("expected refresh rejection, got %d for body %q", res.Code, body)
		}
	}
}

func TestIdentityPersistenceErrors(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	registerStore := newFakeIdentityStore()
	registerStore.createUserErr = errors.New("db down")
	registerHandler := New(registerStore, privateKey, &privateKey.PublicKey, nil)
	registerReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{
		"email":"juan@example.com",
		"password":"Secure!1234",
		"role":"patient",
		"first_name":"Juan",
		"last_name":"Perez"
	}`))
	registerRes := httptest.NewRecorder()
	registerHandler.Register(registerRes, registerReq)
	if registerRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected register 500, got %d", registerRes.Code)
	}

	refreshStore := newFakeIdentityStore()
	user := models.User{ID: "usr_1", Email: "juan@example.com", Role: models.RolePatient, EmailVerified: true}
	refreshStore.usersByID[user.ID] = user
	token, jti, err := signRefreshForTest(privateKey, user.ID, user.Role)
	if err != nil {
		t.Fatalf("signRefreshForTest: %v", err)
	}
	refreshStore.sessions[jti] = models.Session{ID: jti, UserID: user.ID, Kind: "refresh", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	refreshStore.deleteErr = errors.New("delete failed")
	refreshHandler := New(refreshStore, privateKey, &privateKey.PublicKey, nil)
	refreshReq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+token+`"}`))
	refreshRes := httptest.NewRecorder()
	refreshHandler.Refresh(refreshRes, refreshReq)
	if refreshRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected refresh 500, got %d", refreshRes.Code)
	}

	sessionStore := newFakeIdentityStore()
	sessionStore.usersByID[user.ID] = user
	token, jti, err = signRefreshForTest(privateKey, user.ID, user.Role)
	if err != nil {
		t.Fatalf("signRefreshForTest: %v", err)
	}
	sessionStore.sessions[jti] = models.Session{ID: jti, UserID: user.ID, Kind: "refresh", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	sessionStore.sessionErr = errors.New("session insert failed")
	sessionHandler := New(sessionStore, privateKey, &privateKey.PublicKey, nil)
	sessionReq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+token+`"}`))
	sessionRes := httptest.NewRecorder()
	sessionHandler.Refresh(sessionRes, sessionReq)
	if sessionRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected session refresh 500, got %d", sessionRes.Code)
	}

	loginStore := newFakeIdentityStore()
	loginUser := models.User{
		ID:            "usr_login",
		Email:         "login@example.com",
		Role:          models.RolePatient,
		EmailVerified: true,
	}
	loginUser.PasswordHash, _ = security.HashPassword("Secure!1234")
	loginStore.usersByID[loginUser.ID] = loginUser
	loginStore.usersByEmail[loginUser.Email] = loginUser
	loginStore.sessionErr = errors.New("session insert failed")
	loginHandler := New(loginStore, privateKey, &privateKey.PublicKey, nil)
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"login@example.com","password":"Secure!1234"}`))
	loginRes := httptest.NewRecorder()
	loginHandler.LoginMobile(loginRes, loginReq)
	if loginRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected login session 500, got %d", loginRes.Code)
	}
}

func TestLogoutWebAndMobile(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	fakeStore := newFakeIdentityStore()
	fakeStore.sessions["ses_123"] = models.Session{ID: "ses_123", UserID: "usr_123"}
	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	// Logout mobile
	reqMob := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	reqMob = reqMob.WithContext(authz.WithClaims(reqMob.Context(), &security.Claims{UserID: "usr_123", Role: "patient"}))
	resMob := httptest.NewRecorder()
	handler.LogoutMobile(resMob, reqMob)
	if resMob.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resMob.Code)
	}

	// Logout web
	fakeStore.sessions["ses_456"] = models.Session{ID: "ses_456", UserID: "usr_456"}
	reqWeb := httptest.NewRequest(http.MethodPost, "/v1/auth/web/logout", nil)
	reqWeb = reqWeb.WithContext(authz.WithClaims(reqWeb.Context(), &security.Claims{UserID: "usr_456", Role: "patient"}))
	resWeb := httptest.NewRecorder()
	handler.LogoutWeb(resWeb, reqWeb)
	if resWeb.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resWeb.Code)
	}
	if len(resWeb.Result().Cookies()) == 0 {
		t.Fatalf("expected expired cookies in logout web response")
	}
}

func signRefreshForTest(privateKey *rsa.PrivateKey, userID, role string) (string, string, error) {
	return security.SignJWT(privateKey, userID, role, "refresh", 7*24*time.Hour)
}
