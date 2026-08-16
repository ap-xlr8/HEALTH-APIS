package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	auditLogs     []models.AuditLog
}

func newFakeIdentityStore() *fakeIdentityStore {
	return &fakeIdentityStore{
		usersByEmail: map[string]models.User{},
		usersByID:    map[string]models.User{},
		sessions:     map[string]models.Session{},
	}
}

func (f *fakeIdentityStore) WriteAudit(ctx context.Context, log models.AuditLog) error {
	f.auditLogs = append(f.auditLogs, log)
	return nil
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

func (f *fakeIdentityStore) SetUserTwoFactorCode(ctx context.Context, userID, code string, expiresAt time.Time) error {
	for id, u := range f.usersByID {
		if id == userID {
			u.TwoFactorCode = code
			u.TwoFactorExpiresAt = &expiresAt
			f.usersByID[id] = u
			f.usersByEmail[u.Email] = u
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeIdentityStore) VerifyUserTwoFactorCode(ctx context.Context, email, code string) (models.User, error) {
	u, ok := f.usersByEmail[email]
	if !ok || u.TwoFactorCode != code || (u.TwoFactorExpiresAt != nil && u.TwoFactorExpiresAt.Before(time.Now().UTC())) {
		return models.User{}, store.ErrNotFound
	}
	u.TwoFactorCode = ""
	u.TwoFactorExpiresAt = nil
	u.EmailVerified = true
	f.usersByID[u.ID] = u
	f.usersByEmail[u.Email] = u
	return u, nil
}

func (f *fakeIdentityStore) ClearUserTwoFactorCode(ctx context.Context, userID string) error {
	for id, u := range f.usersByID {
		if id == userID {
			u.TwoFactorCode = ""
			u.TwoFactorExpiresAt = nil
			f.usersByID[id] = u
			f.usersByEmail[u.Email] = u
			return nil
		}
	}
	return store.ErrNotFound
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

func (f *fakeIdentityStore) SetUserPasswordResetToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	for id, u := range f.usersByID {
		if id == userID {
			u.PasswordResetToken = token
			u.PasswordResetExpiresAt = &expiresAt
			f.usersByID[id] = u
			f.usersByEmail[u.Email] = u
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeIdentityStore) FindUserByPasswordResetToken(ctx context.Context, token string) (models.User, error) {
	for _, u := range f.usersByID {
		if u.PasswordResetToken == token {
			return u, nil
		}
	}
	return models.User{}, store.ErrNotFound
}

func (f *fakeIdentityStore) ResetUserPassword(ctx context.Context, token, passwordHash string) (models.User, error) {
	for id, u := range f.usersByID {
		if u.PasswordResetToken == token {
			if u.PasswordResetExpiresAt != nil && u.PasswordResetExpiresAt.Before(time.Now().UTC()) {
				return models.User{}, store.ErrNotFound
			}
			u.PasswordHash = passwordHash
			u.PasswordResetToken = ""
			u.PasswordResetExpiresAt = nil
			f.usersByID[id] = u
			f.usersByEmail[u.Email] = u
			return u, nil
		}
	}
	return models.User{}, store.ErrNotFound
}

func (f *fakeIdentityStore) GetUserPreferences(ctx context.Context, userID string) (models.UserPreferences, error) {
	if u, ok := f.usersByID[userID]; ok && u.Preferences != nil {
		return *u.Preferences, nil
	}
	return models.UserPreferences{Theme: "system", Language: "es"}, nil
}

func (f *fakeIdentityStore) UpdateUserPreferences(ctx context.Context, userID string, prefs models.UserPreferences) error {
	if u, ok := f.usersByID[userID]; ok {
		u.Preferences = &prefs
		f.usersByID[userID] = u
		return nil
	}
	return store.ErrNotFound
}

func (f *fakeIdentityStore) UpdateCaregiverProfile(ctx context.Context, userID string, profile models.CaregiverProfile) error {
	if u, ok := f.usersByID[userID]; ok {
		u.CaregiverProfile = &profile
		f.usersByID[userID] = u
		return nil
	}
	return store.ErrNotFound
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
	if registerRes.Code != http.StatusOK {
		t.Fatalf("expected register 200, got %d body=%s", registerRes.Code, registerRes.Body.String())
	}

	savedUser, ok := fakeStore.usersByEmail["juan@example.com"]
	if !ok || savedUser.TwoFactorCode == "" {
		t.Fatalf("expected saved user with 2fa code in store")
	}
	otpCode := savedUser.TwoFactorCode

	// Complete 2FA after registration
	verify2FAReq := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/verify", strings.NewReader(`{"email":"juan@example.com","code":"`+otpCode+`"}`))
	verify2FARes := httptest.NewRecorder()
	handler.Verify2FAMobile(verify2FARes, verify2FAReq)
	if verify2FARes.Code != http.StatusOK {
		t.Fatalf("expected 2fa verify 200, got %d body=%s", verify2FARes.Code, verify2FARes.Body.String())
	}

	// Login triggers 2FA challenge
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"juan@example.com","password":"Secure!1234"}`))
	loginRes := httptest.NewRecorder()
	handler.LoginMobile(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d body=%s", loginRes.Code, loginRes.Body.String())
	}
	var loginChallenge struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(loginRes.Body.Bytes(), &loginChallenge); err != nil || loginChallenge.Status != "2fa_required" {
		t.Fatalf("expected 2fa_required status, got %s", loginRes.Body.String())
	}

	// Verify 2FA on login
	loginOtp := fakeStore.usersByEmail["juan@example.com"].TwoFactorCode
	verifyLogin2FAReq := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/verify", strings.NewReader(`{"email":"juan@example.com","code":"`+loginOtp+`"}`))
	verifyLogin2FARes := httptest.NewRecorder()
	handler.Verify2FAMobile(verifyLogin2FARes, verifyLogin2FAReq)
	if verifyLogin2FARes.Code != http.StatusOK {
		t.Fatalf("expected login 2fa verify 200, got %d body=%s", verifyLogin2FARes.Code, verifyLogin2FARes.Body.String())
	}

	var loginPayload struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(verifyLogin2FARes.Body.Bytes(), &loginPayload); err != nil {
		t.Fatalf("login json: %v", err)
	}
	if loginPayload.RefreshToken == "" || len(fakeStore.sessions) < 1 {
		t.Fatalf("expected refresh token and session, sessions=%d", len(fakeStore.sessions))
	}

	refreshReq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+loginPayload.RefreshToken+`"}`))
	refreshRes := httptest.NewRecorder()
	handler.Refresh(refreshRes, refreshReq)
	if refreshRes.Code != http.StatusOK {
		t.Fatalf("expected refresh 200, got %d body=%s", refreshRes.Code, refreshRes.Body.String())
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

	otpCode := fakeStore.usersByEmail["doc@example.com"].TwoFactorCode
	if otpCode == "" {
		t.Fatalf("expected 2fa code generated on login")
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/web/verify", strings.NewReader(`{"email":"doc@example.com","code":"`+otpCode+`"}`))
	verifyRes := httptest.NewRecorder()
	handler.Verify2FAWeb(verifyRes, verifyReq)

	if verifyRes.Code != http.StatusOK {
		t.Fatalf("expected 2fa web verify 200, got %d body=%s", verifyRes.Code, verifyRes.Body.String())
	}

	cookies := verifyRes.Result().Cookies()
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
		TwoFactorCode: "654321",
	}
	loginUser.PasswordHash, _ = security.HashPassword("Secure!1234")
	loginStore.usersByID[loginUser.ID] = loginUser
	loginStore.usersByEmail[loginUser.Email] = loginUser
	loginStore.sessionErr = errors.New("session insert failed")
	loginHandler := New(loginStore, privateKey, &privateKey.PublicKey, nil)
	verifyReq := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/verify", strings.NewReader(`{"email":"login@example.com","code":"654321"}`))
	verifyRes := httptest.NewRecorder()
	loginHandler.Verify2FAMobile(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected 2fa verify session 500, got %d", verifyRes.Code)
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

func TestForgotPasswordAndResetPassword(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	fakeStore := newFakeIdentityStore()
	user := models.User{ID: "usr_1", Email: "juan@example.com", Role: models.RolePatient, FirstName: "Juan"}
	user.PasswordHash, _ = security.HashPassword("Old!Pass123")
	fakeStore.usersByID[user.ID] = user
	fakeStore.usersByEmail[user.Email] = user
	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	// 1. Request reset token
	forgotReq := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(`{"email":"juan@example.com"}`))
	forgotRes := httptest.NewRecorder()
	handler.ForgotPassword(forgotRes, forgotReq)
	if forgotRes.Code != http.StatusOK {
		t.Fatalf("expected forgot 200, got %d body=%s", forgotRes.Code, forgotRes.Body.String())
	}
	token := fakeStore.usersByID["usr_1"].PasswordResetToken
	if token == "" {
		t.Fatal("expected reset token stored in fake store")
	}

	// 2. GET page renders form with token
	pageReq := httptest.NewRequest(http.MethodGet, "/reset-password?token="+token, nil)
	pageRes := httptest.NewRecorder()
	handler.ResetPasswordPage(pageRes, pageReq)
	if pageRes.Code != http.StatusOK || !strings.Contains(pageRes.Body.String(), "Restablece tu contraseña") || !strings.Contains(pageRes.Body.String(), token) {
		t.Fatalf("expected reset form page with token, got %d body=%s", pageRes.Code, pageRes.Body.String())
	}

	// 3. POST form resets password
	form := url.Values{
		"token":            {token},
		"new_password":     {"New!Pass123"},
		"confirm_password": {"New!Pass123"},
	}
	formReq := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(form.Encode()))
	formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formRes := httptest.NewRecorder()
	handler.ResetPasswordPage(formRes, formReq)
	if formRes.Code != http.StatusOK || !strings.Contains(formRes.Body.String(), "Contraseña actualizada") {
		t.Fatalf("expected success page, got %d body=%s", formRes.Code, formRes.Body.String())
	}

	// 4. Old token is now single-use: API reset with same token must fail
	resetReq := httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(`{"token":"`+token+`","new_password":"New!Pass123"}`))
	resetRes := httptest.NewRecorder()
	handler.ResetPassword(resetRes, resetReq)
	if resetRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for reused token, got %d body=%s", resetRes.Code, resetRes.Body.String())
	}

	// 5. New password actually stored
	saved := fakeStore.usersByID["usr_1"]
	if !security.CheckPassword(saved.PasswordHash, "New!Pass123") {
		t.Fatal("expected stored password hash to match new password")
	}
}

func TestResetPasswordValidatesPolicy(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	fakeStore := newFakeIdentityStore()
	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	for name, password := range map[string]string{
		"too short": "abc",
		"no symbol": "Password123",
		"no digit":  "Password!!!",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(`{"token":"tok","new_password":"`+password+`"}`))
			res := httptest.NewRecorder()
			handler.ResetPassword(res, req)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", res.Code)
			}
		})
	}
}

func TestForgotPasswordDoesNotRevealAccount(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	handler := New(newFakeIdentityStore(), privateKey, &privateKey.PublicKey, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(`{"email":"nobody@example.com"}`))
	res := httptest.NewRecorder()
	handler.ForgotPassword(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown email, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "Si el correo está registrado") {
		t.Fatalf("expected non-revealing message, got %s", res.Body.String())
	}
}

func signRefreshForTest(privateKey *rsa.PrivateKey, userID, role string) (string, string, error) {
	return security.SignJWT(privateKey, userID, role, "refresh", 7*24*time.Hour)
}

func newTestIdentityHandler() (Handler, *fakeIdentityStore) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	fakeStore := newFakeIdentityStore()
	return New(fakeStore, privateKey, &privateKey.PublicKey, nil), fakeStore
}

func TestVerifyEmailPaths(t *testing.T) {
	t.Parallel()
	handler, fakeStore := newTestIdentityHandler()
	user := models.User{ID: "usr_v", Email: "verify@example.com", VerificationToken: "tok-verify-1"}
	fakeStore.usersByID["usr_v"] = user
	fakeStore.usersByEmail["verify@example.com"] = user

	// 1. JSON body
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify-email", strings.NewReader(`{"token":"tok-verify-1"}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.VerifyEmail(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}

	// 2. Query parameter (resets user token)
	user2 := models.User{ID: "usr_v2", Email: "verify2@example.com", VerificationToken: "tok-verify-2"}
	fakeStore.usersByID["usr_v2"] = user2
	fakeStore.usersByEmail["verify2@example.com"] = user2
	req2 := httptest.NewRequest(http.MethodGet, "/v1/auth/verify-email?token=tok-verify-2", nil)
	res2 := httptest.NewRecorder()
	handler.VerifyEmail(res2, req2)
	if res2.Code != http.StatusOK {
		t.Fatalf("expected 200 via query, got %d body=%s", res2.Code, res2.Body.String())
	}

	// 3. Missing token
	req3 := httptest.NewRequest(http.MethodGet, "/v1/auth/verify-email", nil)
	res3 := httptest.NewRecorder()
	handler.VerifyEmail(res3, req3)
	if res3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", res3.Code)
	}

	// 4. Invalid token
	req4 := httptest.NewRequest(http.MethodGet, "/v1/auth/verify-email?token=nope", nil)
	res4 := httptest.NewRecorder()
	handler.VerifyEmail(res4, req4)
	if res4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid token, got %d", res4.Code)
	}
}

func TestResend2FAPaths(t *testing.T) {
	t.Parallel()
	handler, fakeStore := newTestIdentityHandler()
	user := models.User{ID: "usr_2fa", Email: "resend@example.com"}
	fakeStore.usersByID["usr_2fa"] = user
	fakeStore.usersByEmail["resend@example.com"] = user

	// 1. Success
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/resend", strings.NewReader(`{"email":"resend@example.com"}`))
	res := httptest.NewRecorder()
	handler.Resend2FA(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	if fakeStore.usersByID["usr_2fa"].TwoFactorCode == "" {
		t.Fatal("expected new 2fa code to be stored")
	}

	// 2. Invalid JSON
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/resend", strings.NewReader(`not-json`))
	res2 := httptest.NewRecorder()
	handler.Resend2FA(res2, req2)
	if res2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json, got %d", res2.Code)
	}

	// 3. Empty email
	req3 := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/resend", strings.NewReader(`{"email":"  "}`))
	res3 := httptest.NewRecorder()
	handler.Resend2FA(res3, req3)
	if res3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty email, got %d", res3.Code)
	}

	// 4. Unknown email
	req4 := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/resend", strings.NewReader(`{"email":"nobody@example.com"}`))
	res4 := httptest.NewRecorder()
	handler.Resend2FA(res4, req4)
	if res4.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown email, got %d", res4.Code)
	}
}

func TestMePaths(t *testing.T) {
	t.Parallel()
	handler, fakeStore := newTestIdentityHandler()
	user := models.User{ID: "usr_me", Email: "me@example.com", FirstName: "Ana", LastName: "Garcia", Role: models.RolePatient, CreatedAt: time.Now().UTC()}
	fakeStore.usersByID["usr_me"] = user
	fakeStore.usersByEmail["me@example.com"] = user

	// 1. Unauthenticated
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/me", nil)
	res := httptest.NewRecorder()
	handler.Me(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without claims, got %d", res.Code)
	}

	// 2. Success
	ctx := authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_me", Role: models.RolePatient})
	req2 := httptest.NewRequest(http.MethodGet, "/v1/profile/me", nil).WithContext(ctx)
	res2 := httptest.NewRecorder()
	handler.Me(res2, req2)
	if res2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res2.Code, res2.Body.String())
	}
	if !strings.Contains(res2.Body.String(), "Ana Garcia") {
		t.Fatalf("expected full name in body, got %s", res2.Body.String())
	}

	// 3. Name falls back to email
	userNoName := models.User{ID: "usr_nn", Email: "noname@example.com"}
	fakeStore.usersByID["usr_nn"] = userNoName
	fakeStore.usersByEmail["noname@example.com"] = userNoName
	ctx3 := authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_nn"})
	req3 := httptest.NewRequest(http.MethodGet, "/v1/profile/me", nil).WithContext(ctx3)
	res3 := httptest.NewRecorder()
	handler.Me(res3, req3)
	if res3.Code != http.StatusOK || !strings.Contains(res3.Body.String(), "noname@example.com") {
		t.Fatalf("expected email fallback name, got %d body=%s", res3.Code, res3.Body.String())
	}

	// 4. Unknown user
	ctx4 := authz.WithClaims(req.Context(), &security.Claims{UserID: "missing"})
	req4 := httptest.NewRequest(http.MethodGet, "/v1/profile/me", nil).WithContext(ctx4)
	res4 := httptest.NewRecorder()
	handler.Me(res4, req4)
	if res4.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown user, got %d", res4.Code)
	}
}

func TestPasswordResetURLAndBloodType(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/reset-password", nil)
	req.Host = "healthos.app"
	url := passwordResetURL(req, "tok123")
	if url != "http://healthos.app/reset-password?token=tok123" {
		t.Fatalf("unexpected dev url %q", url)
	}

	req.Header.Set("X-Forwarded-Proto", "https")
	if got := passwordResetURL(req, "tok123"); got != "https://healthos.app/reset-password?token=tok123" {
		t.Fatalf("unexpected https url %q", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/reset-password", nil)
	req2.Host = ""
	req2.Header.Set("X-Forwarded-Proto", "http")
	if got := passwordResetURL(req2, "t"); got != "http://localhost:8080/reset-password?token=t" {
		t.Fatalf("unexpected fallback url %q", got)
	}

	for valid, want := range map[string]bool{
		"O+": true, "a-": true, "AB+": true, "b+": true,
		"": false, "Z-": false, "AB0": false, "o++": false,
	} {
		if got := validBloodType(valid); got != want {
			t.Fatalf("validBloodType(%q) = %v, want %v", valid, got, want)
		}
	}
}

func TestValidateRegisterExtraBranches(t *testing.T) {
	t.Parallel()
	base := registerRequest{
		Email:     "juan@example.com",
		Password:  "Secure!1234",
		Role:      "patient",
		FirstName: "Juan",
		LastName:  "Perez",
	}
	cases := map[string]func(*registerRequest){
		"age too high": func(r *registerRequest) { r.Age = 121 },
		"weight too low": func(r *registerRequest) {
			r.HealthProfile = &models.HealthProfile{WeightKg: 10, HeightCm: 170, BloodType: "O+"}
		},
		"height too high": func(r *registerRequest) {
			r.HealthProfile = &models.HealthProfile{WeightKg: 70, HeightCm: 260, BloodType: "O+"}
		},
		"bad blood type": func(r *registerRequest) {
			r.HealthProfile = &models.HealthProfile{WeightKg: 70, HeightCm: 170, BloodType: "X+"}
		},
		"too many conditions": func(r *registerRequest) {
			for i := 0; i < 21; i++ {
				r.ActiveConditions = append(r.ActiveConditions, "condition")
			}
		},
		"blank condition": func(r *registerRequest) { r.ActiveConditions = []string{"ok", "  "} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := base
			mutate(&req)
			if err := validateRegister(req); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}

	ok := base
	ok.HealthProfile = &models.HealthProfile{WeightKg: 70, HeightCm: 170, BloodType: "ab+"}
	ok.ActiveConditions = []string{"Hipertensión"}
	if err := validateRegister(ok); err != nil {
		t.Fatalf("expected valid registration with health profile, got %v", err)
	}
}

func TestResetPasswordPageMethods(t *testing.T) {
	t.Parallel()
	handler, _ := newTestIdentityHandler()

	// PUT is not allowed
	req := httptest.NewRequest(http.MethodPut, "/reset-password", nil)
	res := httptest.NewRecorder()
	handler.ResetPasswordPage(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for PUT, got %d", res.Code)
	}

	// GET renders form
	req2 := httptest.NewRequest(http.MethodGet, "/reset-password", nil)
	res2 := httptest.NewRecorder()
	handler.ResetPasswordPage(res2, req2)
	if res2.Code != http.StatusOK || !strings.Contains(res2.Body.String(), "Restablecer contraseña") {
		t.Fatalf("expected reset form page, got %d", res2.Code)
	}

	// Invalid form body
	req3 := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader("%%%invalid"))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res3 := httptest.NewRecorder()
	handler.ResetPasswordPage(res3, req3)
	if res3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid form, got %d", res3.Code)
	}

	// Missing token renders error inside form
	req4 := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader("new_password=abc&confirm_password=abc"))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res4 := httptest.NewRecorder()
	handler.ResetPasswordPage(res4, req4)
	if res4.Code != http.StatusOK || !strings.Contains(res4.Body.String(), "Enlace de restablecimiento inválido") {
		t.Fatalf("expected invalid-token form message, got %d body=%s", res4.Code, res4.Body.String())
	}

	// Mismatched passwords
	req5 := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader("token=tok&new_password=abc&confirm_password=def"))
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res5 := httptest.NewRecorder()
	handler.ResetPasswordPage(res5, req5)
	if res5.Code != http.StatusOK || !strings.Contains(res5.Body.String(), "Las contraseñas no coinciden") {
		t.Fatalf("expected mismatch message, got %d body=%s", res5.Code, res5.Body.String())
	}
}

func TestSensitiveEventsAreAudited(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	fakeStore := newFakeIdentityStore()
	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	registerReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{
		"email":"audit@example.com",
		"password":"Secure!1234",
		"role":"patient",
		"first_name":"Ana",
		"last_name":"Lopez"
	}`))
	registerRes := httptest.NewRecorder()
	handler.Register(registerRes, registerReq)
	if registerRes.Code != http.StatusOK {
		t.Fatalf("register: got %d body=%s", registerRes.Code, registerRes.Body.String())
	}

	// Failed login (wrong password) must be denied in the audit trail.
	failedLoginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"audit@example.com","password":"WrongPass!1"}`))
	failedLoginRes := httptest.NewRecorder()
	handler.LoginMobile(failedLoginRes, failedLoginReq)
	if failedLoginRes.Code != http.StatusUnauthorized {
		t.Fatalf("failed login: got %d body=%s", failedLoginRes.Code, failedLoginRes.Body.String())
	}

	// Successful login (2FA challenge issued).
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"audit@example.com","password":"Secure!1234"}`))
	loginRes := httptest.NewRecorder()
	handler.LoginMobile(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("login: got %d body=%s", loginRes.Code, loginRes.Body.String())
	}

	// Complete 2FA.
	otp := fakeStore.usersByEmail["audit@example.com"].TwoFactorCode
	verifyReq := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/verify", strings.NewReader(`{"email":"audit@example.com","code":"`+otp+`"}`))
	verifyRes := httptest.NewRecorder()
	handler.Verify2FAMobile(verifyRes, verifyReq)
	if verifyRes.Code != http.StatusOK {
		t.Fatalf("verify 2fa: got %d body=%s", verifyRes.Code, verifyRes.Body.String())
	}
	var loginPayload struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(verifyRes.Body.Bytes(), &loginPayload); err != nil {
		t.Fatalf("verify 2fa json: %v", err)
	}

	// Refresh token rotation.
	refreshReq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+loginPayload.RefreshToken+`"}`))
	refreshRes := httptest.NewRecorder()
	handler.Refresh(refreshRes, refreshReq)
	if refreshRes.Code != http.StatusOK {
		t.Fatalf("refresh: got %d body=%s", refreshRes.Code, refreshRes.Body.String())
	}

	// Password reset request.
	forgotReq := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(`{"email":"audit@example.com"}`))
	forgotRes := httptest.NewRecorder()
	handler.ForgotPassword(forgotRes, forgotReq)
	if forgotRes.Code != http.StatusOK {
		t.Fatalf("forgot password: got %d body=%s", forgotRes.Code, forgotRes.Body.String())
	}

	// Reset password with an invalid token must be denied in the audit trail.
	resetReq := httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(`{"token":"bad-token","new_password":"NewPass!4567"}`))
	resetRes := httptest.NewRecorder()
	handler.ResetPassword(resetRes, resetReq)
	if resetRes.Code != http.StatusBadRequest {
		t.Fatalf("reset password: got %d body=%s", resetRes.Code, resetRes.Body.String())
	}

	// Logout.
	logoutReq := httptest.NewRequest(http.MethodPost, "/v1/auth/web/logout", nil)
	logoutReq = logoutReq.WithContext(authz.WithClaims(logoutReq.Context(), &security.Claims{UserID: fakeStore.usersByEmail["audit@example.com"].ID, Role: models.RolePatient}))
	logoutRes := httptest.NewRecorder()
	handler.LogoutWeb(logoutRes, logoutReq)
	if logoutRes.Code != http.StatusOK {
		t.Fatalf("logout: got %d body=%s", logoutRes.Code, logoutRes.Body.String())
	}

	want := []struct {
		action  string
		allowed bool
	}{
		{action: "auth.register", allowed: true},
		{action: "auth.login", allowed: false},
		{action: "auth.login", allowed: true},
		{action: "auth.2fa", allowed: true},
		{action: "auth.token_refresh", allowed: true},
		{action: "auth.password_reset_request", allowed: true},
		{action: "auth.password_reset", allowed: false},
		{action: "auth.logout", allowed: true},
	}
	if len(fakeStore.auditLogs) < len(want) {
		t.Fatalf("expected at least %d audit entries, got %d: %#v", len(want), len(fakeStore.auditLogs), fakeStore.auditLogs)
	}
	for i, w := range want {
		entry := fakeStore.auditLogs[i]
		if entry.Action != w.action || entry.Allowed != w.allowed {
			t.Fatalf("audit entry %d: got action=%q allowed=%v, want action=%q allowed=%v", i, entry.Action, entry.Allowed, w.action, w.allowed)
		}
	}
}

func TestPreferencesHandler(t *testing.T) {
	t.Parallel()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fakeStore := newFakeIdentityStore()
	user := models.User{ID: "usr_pref", Email: "pref@example.com", Role: models.RolePatient}
	fakeStore.usersByID[user.ID] = user
	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: user.ID, Role: models.RolePatient})

	// Get Preferences
	getReq := httptest.NewRequest(http.MethodGet, "/v1/profile/me/preferences", nil).WithContext(ctx)
	getRes := httptest.NewRecorder()
	handler.GetPreferences(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("GetPreferences failed: %d", getRes.Code)
	}

	// Update Preferences
	updateBody := `{"theme":"dark","language":"es","notification_channels":["push"],"quiet_hours":{"enabled":true,"start":"23:00","end":"06:00"}}`
	putReq := httptest.NewRequest(http.MethodPut, "/v1/profile/me/preferences", strings.NewReader(updateBody)).WithContext(ctx)
	putRes := httptest.NewRecorder()
	handler.UpdatePreferences(putRes, putReq)
	if putRes.Code != http.StatusOK {
		t.Fatalf("UpdatePreferences failed: %d", putRes.Code)
	}
}

func TestCaregiverProfileHandler(t *testing.T) {
	t.Parallel()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fakeStore := newFakeIdentityStore()
	user := models.User{ID: "cg_1", Email: "cg@example.com", Role: models.RoleCaregiver}
	fakeStore.usersByID[user.ID] = user
	handler := New(fakeStore, privateKey, &privateKey.PublicKey, nil)

	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: user.ID, Role: models.RoleCaregiver})

	body := `{"phone":"+525511223344","specialty":"Cardiologia Geriatrica","organization":"Clinica Santa Maria","bio":"Especialista con 15 anos de experiencia."}`
	putReq := httptest.NewRequest(http.MethodPut, "/v1/profile/caregiver", strings.NewReader(body)).WithContext(ctx)
	putRes := httptest.NewRecorder()
	handler.UpdateCaregiverProfile(putRes, putReq)
	if putRes.Code != http.StatusOK {
		t.Fatalf("UpdateCaregiverProfile failed: %d", putRes.Code)
	}
}

