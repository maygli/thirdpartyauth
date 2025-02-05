package auththirdparty

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// Google service name
	GOOGLE_SERVICE_NAME = "google"
	// Google email scope
	AUTH_GOOGLE_EMAIL_SCOPE = "https://www.googleapis.com/auth/userinfo.email"
	// Google profile scope
	AUTH_GOOGLE_PROFILE_SCOPE = "https://www.googleapis.com/auth/userinfo.profile"
	// Google get user method
	GOOGLE_GET_USER_METHOD = http.MethodGet
	// Google get profile url
	GOOGLE_USER_PROFILE_DATA_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
	// Google oauth api url
	GOOGLE_OAUTH_API_URL = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
)

// User structure returned by Google
type GoogleUser struct {
	// User id
	UserId string `json:"id"`
	// Email
	Email string `json:"email"`
	// First name
	FirstName string `json:"given_name"`
	// Last name
	LastName string `json:"family_name"`
	// Avator
	Avatar string `json:"picture"`
}

// Google authorization service configuration
type GoogleAuthConfigure struct {
	// Google client id (must specified)
	GoogleClientId string `json:"google_client_id" env:"${SERVER_NAME}_AUTH_GOOGLE_CLIENT_ID"`
	// Google client secret (must specified)
	GoogleClientSecret string `json:"google_client_secret" env:"${SERVER_NAME}_AUTH_GOOGLE_CLIENT_SECRET"`
	// Service address. Should be the same as registered in Google
	ServerAddress string `json:"server_address" env:"${SERVER_NAME}_SERVER_ADDRESS"`
	// Login endpoint. Can be empty. In this case '/auth/google/login' will be used
	LoginEndPoint string `json:"google_login_endpoint" env:"${SERVER_NAME}_GOOGLE_LOGIN_ENDPOINT" default:"/auth/google/login"`
	// Callback endpoint. Can be empty. In this case '/auth/google/callback' will be used
	CallbackEndPoint string `json:"google_callback_endpoint" env:"${SERVER_NAME}_GOOGLE_CALLBACK_ENDPOINT" default:"/auth/google/callback"`
}

// Google authorization service structure
type GoogleAuthService struct {
	AuthThirdPartyBase
	googleLoginConfig oauth2.Config
}

// Create Google authorization structure.
// Parameters:
//   - config Google authorization service config
//   - processor complete processor
//
// Returns:
//
//	pointer to Google authorization service structure
func NewGoogleAuthService(config GoogleAuthConfigure, processor CompleteAuthProcessor) *GoogleAuthService {
	service := GoogleAuthService{
		AuthThirdPartyBase: AuthThirdPartyBase{
			LoginEndPoint:    config.LoginEndPoint,
			CallbackEndPoint: config.CallbackEndPoint,
			AuthProcessor:    processor,
		},
	}
	service.googleLoginConfig = oauth2.Config{
		RedirectURL:  config.ServerAddress + service.GetCallbackEndpoint(service.GetServiceName()),
		ClientID:     config.GoogleClientId,
		ClientSecret: config.GoogleClientSecret,
		Scopes: []string{AUTH_GOOGLE_EMAIL_SCOPE,
			AUTH_GOOGLE_PROFILE_SCOPE},
		Endpoint: google.Endpoint,
	}
	return &service
}

// Return service name ('google').
//
// Returns:
//
//	service name
func (service GoogleAuthService) GetServiceName() string {
	return GOOGLE_SERVICE_NAME
}

// Login endpoint.
//
// Parameters:
//   - w response writter
//   - r http request
func (service GoogleAuthService) googleAuthLoginHandle(w http.ResponseWriter, r *http.Request) {
	ProcessLogin(w, r, service.googleLoginConfig)
}

// Get Google user data by received token.
//
// Parameters:
//   - token token received by Google
//
// Returns:
//
//	received data or error
func (service GoogleAuthService) getUserDataFromGoogle(token *oauth2.Token) (GoogleUser, error) {
	client := service.googleLoginConfig.Client(context.Background(), token)
	response, err := client.Get(GOOGLE_OAUTH_API_URL + token.AccessToken)
	if err != nil {
		return GoogleUser{}, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return GoogleUser{}, err
	}
	user := GoogleUser{}
	err = json.Unmarshal(content, &user)
	return user, err
}

// Convert data received from Google to AuthThirdPartyUser.
//
// Parameters:
//   - user data received from Google
//
// Returns:
//
//	AuthThirdPartyUser
func googleToAuthUser(user GoogleUser) AuthThirdPartyUser {
	resUser := AuthThirdPartyUser{
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		Avatar:    user.Avatar,
		UserId:    user.UserId,
		Service:   GOOGLE_SERVICE_NAME,
	}
	return resUser
}

// Google authorization service callback handle.
//
// Parameters:
//   - w response writter
//   - r http request
func (service GoogleAuthService) googleAuthCallbackHandle(w http.ResponseWriter, r *http.Request) {
	token, err := GetToken(r, service.googleLoginConfig)
	if err != nil {
		service.ProcessError(err, w, r)
		return
	}
	user, err := service.getUserDataFromGoogle(token)
	if err != nil {
		service.ProcessError(err, w, r)
		return
	}
	gUser := googleToAuthUser(user)
	err = service.ProcessSuccess(gUser, w, r)
	if err != nil {
	}
}

// Registered Google authorization service endpoints.
//
// Parameters:
//   - mux server mux
func (service GoogleAuthService) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET "+service.GetLoginEndpoint(service.GetServiceName()), service.googleAuthLoginHandle)
	mux.HandleFunc("GET "+service.GetCallbackEndpoint(service.GetServiceName()), service.googleAuthCallbackHandle)
}
