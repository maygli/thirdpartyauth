package auththirdparty

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yandex"
)

const (
	// Yandex service name
	YANDEX_SERVICE_NAME = "yandex"
	// Yandex email scope
	AUTH_YANDEX_SCOPE_EMAIL = "login:email"
	// Yandex info scope
	AUTH_YANDEX_SCOPE_INFO = "login:info"
	// Yandex avatar URL
	AUTH_YANDEX_SCOPE_AVATAR = "login:avatar"
	// Yandex get user info URL
	AUTH_YANDEX_USER_INFO_URL = "https://login.yandex.ru/info?format=json"
	YANDEX_OAUTH              = "OAuth "
)

// User data structure sent by Yandex.
type YandexUser struct {
	// User id
	UserId string `json:"id"`
	// Email
	Email string `json:"default_email"`
	// First name
	FirstName string `json:"first_name"`
	// Last name
	LastName string `json:"last_name"`
	// Avatar url
	Avatar string `json:"default_avatar_id"`
	// Login
	Login string `json:"login"`
}

// Yandex authorization service configuration
type YandexAuthConfigure struct {
	// Yandex client id (must specified)
	YandexClientId string `json:"yandex_client_id" env:"${SERVER_NAME}_AUTH_YANDEX_CLIENT_ID"`
	// Yandex client secret (must specified)
	YandexClientSecret string `json:"yandex_client_secret" env:"${SERVER_NAME}_AUTH_YANDEX_CLIENT_SECRET"`
	// Service address. Should be the same as registered in Yandexgo
	ServerAddress string `json:"server_address" env:"${SERVER_NAME}_SERVER_ADDRESS"`
	// Login endpoint. Can be empty. In this case '/auth/yandex/login' will be used
	LoginEndPoint string `json:"yandex_login_endpoint" env:"${SERVER_NAME}_YANDEX_LOGIN_ENDPOINT" default:"/auth/yandex/login"`
	// Callback endpoint. Can be empty. In this case '/auth/yandex/login' will be used
	CallbackEndPoint string `json:"yandex_callback_endpoint" env:"${SERVER_NAME}_YANDEX_CALLBACK_ENDPOINT" default:"/auth/yandex/callback"`
}

// Yandex authorization service structure
type YandexAuthService struct {
	AuthThirdPartyBase
	yandexLoginConfig oauth2.Config
}

// Create Yandex authorization structure.
// Parameters:
//   - config Yandex authorization service config
//   - processor complete processor
//
// Returns:
//
//	pointer to Yandex authorization service structure
func NewYandexAuthService(config YandexAuthConfigure, processor CompleteAuthProcessor) *YandexAuthService {
	service := YandexAuthService{
		AuthThirdPartyBase: AuthThirdPartyBase{
			LoginEndPoint:    config.LoginEndPoint,
			CallbackEndPoint: config.CallbackEndPoint,
			AuthProcessor:    processor,
		},
	}
	service.yandexLoginConfig = oauth2.Config{
		RedirectURL:  config.ServerAddress + service.GetCallbackEndpoint(service.GetServiceName()),
		ClientID:     config.YandexClientId,
		ClientSecret: config.YandexClientSecret,
		Scopes:       []string{AUTH_YANDEX_SCOPE_INFO, AUTH_YANDEX_SCOPE_EMAIL, AUTH_YANDEX_SCOPE_AVATAR},
		Endpoint:     yandex.Endpoint,
	}
	return &service
}

// Return service name ('yandex').
//
// Returns:
//
//	service name
func (service YandexAuthService) GetServiceName() string {
	return YANDEX_SERVICE_NAME
}

// Login endpoint.
//
// Parameters:
//   - w response writter
//   - r http request
func (service YandexAuthService) yandexAuthLoginHandle(w http.ResponseWriter, r *http.Request) {
	ProcessLogin(w, r, service.yandexLoginConfig)
}

// Get Yandex user data by received token.
//
// Parameters:
//   - token token received by Google
//
// Returns:
//
//	received data or error
func (service YandexAuthService) getUser(token *oauth2.Token) (YandexUser, error) {
	client := service.yandexLoginConfig.Client(context.Background(), token)
	req, err := http.NewRequest(http.MethodGet, AUTH_YANDEX_USER_INFO_URL, nil)
	if err != nil {
		return YandexUser{}, err
	}
	req.Header.Set(AUTH_HEADER, YANDEX_OAUTH+token.AccessToken)
	response, err := client.Do(req)
	if err != nil {
		return YandexUser{}, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return YandexUser{}, err
	}
	user := YandexUser{}
	err = json.Unmarshal(content, &user)
	return user, err
}

// Convert data received from Yandex to AuthThirdPartyUser.
//
// Parameters:
//   - user data received from Vk
//
// Returns:
//
//	AuthThirdPartyUser
func YandexToAuthUser(user YandexUser) AuthThirdPartyUser {
	resUser := AuthThirdPartyUser{
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		Avatar:    user.Avatar,
		UserId:    user.UserId,
		Service:   YANDEX_SERVICE_NAME,
	}
	return resUser
}

// Yandex authorization service callback handle.
//
// Parameters:
//   - w response writter
//   - r http request
func (service YandexAuthService) yandexAuthCallbackHandle(w http.ResponseWriter, r *http.Request) {
	token, err := GetToken(r, service.yandexLoginConfig)
	if err != nil {
		service.ProcessError(err, w, r)
		return
	}
	user, err := service.getUser(token)
	if err != nil {
		service.ProcessError(err, w, r)
		return
	}
	yandexUser := YandexToAuthUser(user)
	err = service.ProcessSuccess(yandexUser, w, r)
	if err != nil {
	}
}

// Registered Yandex authorization service endpoints.
//
// Parameters:
//   - mux server mux
func (service YandexAuthService) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET "+service.GetLoginEndpoint(service.GetServiceName()), service.yandexAuthLoginHandle)
	mux.HandleFunc("GET "+service.GetCallbackEndpoint(service.GetServiceName()), service.yandexAuthCallbackHandle)
}
