package auththirdparty

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	// State symbols lenght
	STATE_LENGTH = 24
	// Verifier symbols lenght
	VERIFIER_LENGHT = 24
	// Life time of state cookie in seconds
	COOKIE_STATE_LIFE_TIME = 600
	// State cookie name
	STATE_COOKIE_NAME = "oauthstate"
	// Verifier cookie name
	VERIFIER_COOKIE_NAME = "verifier"
	// State keyword
	STATE_NAME = "state"
	// Code keyword
	CODE_NAME = "code"
	// Authorization header name
	AUTH_HEADER = "Authorization"
)

// Generates random string.
//
// Parameters:
//   - size string size
//
// Returns:
//
//	random string
func GenerateRandonString(size int) string {
	b := make([]byte, size)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

// Create state cookie.
//
// Parameters:
//   - state state string
//
// Returns:
//
//	generated cookie
func GenerateStateCockie(state string) *http.Cookie {
	expiration := time.Now().Add(COOKIE_STATE_LIFE_TIME * time.Second)
	cookie := http.Cookie{
		Name:     STATE_COOKIE_NAME,
		Value:    state,
		Expires:  expiration,
		HttpOnly: true,
	}
	return &cookie
}

// Create verifier cookie.
//
// Parameters:
//   - verifier verifier string
//
// Returns:
//
//	generated cookie
func GenerateVerifierCockie(verifier string) *http.Cookie {
	expiration := time.Now().Add(COOKIE_STATE_LIFE_TIME * time.Second)
	cookie := http.Cookie{
		Name:     VERIFIER_COOKIE_NAME,
		Value:    verifier,
		Expires:  expiration,
		HttpOnly: true,
	}
	return &cookie
}

// Default process login. (generates state cookie and redirect to generated URL).
//
// Parameters:
//   - w response writter
//   - r http request
//   - config oauth2 config (need to generates redirect URL)
func ProcessLogin(w http.ResponseWriter, r *http.Request, config oauth2.Config) {
	state := GenerateRandonString(STATE_LENGTH)
	url := config.AuthCodeURL(state)
	http.SetCookie(w, GenerateStateCockie(state))
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// Verify cookie value.
//
// Parameters:
//   - r http request
//   - cookieName cookie name to verify
//   - expValue expected value
//
// Returns:
//
//	nil or error
func VerifyCookieValue(r *http.Request, coockieName string, expValue string) error {
	cookieValue, err := r.Cookie(coockieName)
	if err != nil {
		return err
	}
	if cookieValue.Value != expValue {
		return errors.New("invalid cookie value")
	}
	return nil
}

// Get token by code. Check state.
//
// Parameters:
//   - r http request
//   - config oauth config
//
// Returns:
//
//	received token or error
func GetToken(r *http.Request, config oauth2.Config) (*oauth2.Token, error) {
	rsvState := r.FormValue(STATE_NAME)
	if rsvState == "" {
		return nil, errors.New("empty state received")
	}
	err := VerifyCookieValue(r, STATE_COOKIE_NAME, rsvState)
	if err != nil {
		return nil, fmt.Errorf("incorrect state value. Error: %s", err.Error())
	}
	code := r.FormValue(CODE_NAME)
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("can't get token. Error: %s", err.Error())
	}
	return token, nil
}

// Send URL encoded data and receive json response.
//
// Parameters:
//   - methd request method
//   - url request url
//   - data data to sent
//   - result response json data
//
// Returns:
//
//	nil in case of success or error
func SendUrlEncodedReceiveJson(method string, url string, data url.Values, result any) error {
	encodedData := data.Encode()
	req, err := http.NewRequest(method, url, strings.NewReader(encodedData))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(encodedData)))
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(content, result)
	return err
}
