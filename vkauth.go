package auththirdparty

import (
	"errors"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

// User data received from Vk
type VkUser struct {
	// User id
	UserId string `json:"user_id"`
	// First name
	FirstName string `json:"first_name"`
	// Last name
	LastName string `json:"last_name"`
	// Avatar url
	Avatar string `json:"avatar"`
	// Email
	Email string `json:"email"`
}

// Data structure sent by Vk. Vk send user in case of
// success authorization or other fields in case of error
type VkData struct {
	// User data. Send if authorization success
	User VkUser `json:"user"`
	// Authorization error. Send if authorization fail
	Error string `json:"error"`
	// Authorization error description. Send if authorization fail
	ErrorDescription string `json:"error_description"`
	// State to check validity of response
	State string `json:"state"`
}

// Vk authorization service configuration
type VkAuthConfigure struct {
	// Vk client id (must specified)
	VkClientId string `json:"vk_client_id" env:"${SERVER_NAME}_AUTH_VK_CLIENT_ID"`
	// Vk client secret (must specified)
	VkClientSecret string `json:"vk_client_secret" env:"${SERVER_NAME}_AUTH_VK_CLIENT_SECRET"`
	// Service address. Should be the same as registered in Vk
	ServerAddress string `json:"server_address" env:"${SERVER_NAME}_SERVER_ADDRESS"`
	// Login endpoint. Can be empty. In this case '/auth/vk/login' will be used
	LoginEndPoint string `json:"vk_login_endpoint" env:"${SERVER_NAME}_VK_LOGIN_ENDPOINT" default:"/auth/vk/login"`
	// Login endpoint. Can be empty. In this case '/auth/vk/callback' will be used
	CallbackEndPoint string `json:"vk_callback_endpoint" env:"${SERVER_NAME}_VK_CALLBACK_ENDPOINT" default:"/auth/vk/callback"`
}

// Google authorization service structure
type VkAuthService struct {
	AuthThirdPartyBase
	vkLoginConfig oauth2.Config
}

const (
	// Vk authorization service name
	VK_SERVICE_NAME = "vk"
	// Vk email scope
	VK_EMAIL_SCOPE = "email"
	// Vk profile scope
	VK_PROFILE_SCOPE         = "vkid.personal_info"
	VK_AUTH_URL              = "https://id.vk.com/authorize"
	VK_TOKEN_URL             = "https://id.vk.com/oauth2/auth"
	VK_USER_PROFILE_DATA_URL = "https://id.vk.com/oauth2/user_info"
	VK_GET_USER_METHOD       = http.MethodPost
	VK_USER_KEY              = "user"
	ACCESS_TOKEN_KEY         = "access_token"
	CLIENT_ID_KEY            = "client_id"
)

// Create Vk authorization service.
// Parameters:
//   - config Vk authorization service config
//   - processor complete processor
//
// Returns:
//
//	pointer to Google authorization service structure
func NewVkAuthService(config VkAuthConfigure, processor CompleteAuthProcessor) *VkAuthService {
	service := VkAuthService{
		AuthThirdPartyBase: AuthThirdPartyBase{
			LoginEndPoint:    config.LoginEndPoint,
			CallbackEndPoint: config.CallbackEndPoint,
			AuthProcessor:    processor,
		},
	}
	service.vkLoginConfig = oauth2.Config{
		RedirectURL: config.ServerAddress + service.GetCallbackEndpoint(service.GetServiceName()),
		ClientID:    config.VkClientId,
		Scopes:      []string{VK_EMAIL_SCOPE, VK_PROFILE_SCOPE},
		// Oauth2 config for VK is incorrect - so we have set endpoints by 'hand'
		Endpoint: oauth2.Endpoint{
			AuthURL:  VK_AUTH_URL,
			TokenURL: VK_TOKEN_URL,
		},
	}
	return &service
}

// Return service name ('vk').
//
// Returns:
//
//	service name
func (service VkAuthService) GetServiceName() string {
	return VK_SERVICE_NAME
}

// Generate verifier value.
//
// Returns:
//
//	verifier
func (service VkAuthService) generateVerifier() string {
	return GenerateRandonString(VERIFIER_LENGHT)
}

// Login endpoint.
//
// Parameters:
//   - w response writter
//   - r http request
func (service VkAuthService) vkAuthLoginHandle(w http.ResponseWriter, r *http.Request) {
	verifier := service.generateVerifier()
	http.SetCookie(w, GenerateVerifierCockie(verifier))
	codeChallenge := oauth2.S256ChallengeFromVerifier(verifier)
	//	redirect_uri := service.ServerAddress + AUTH_VK_CALLBACK_ENDPOINT
	state := GenerateRandonString(STATE_LENGTH)
	http.SetCookie(w, GenerateStateCockie(state))
	authUrl := service.vkLoginConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge))
	http.Redirect(w, r, authUrl, http.StatusSeeOther)
}

// Convert data received from Vk to AuthThirdPartyUser.
//
// Parameters:
//   - user data received from Vk
//
// Returns:
//
//	AuthThirdPartyUser
func vkToAuthUser(user VkUser) AuthThirdPartyUser {
	resUser := AuthThirdPartyUser{
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		Avatar:    user.Avatar,
		UserId:    user.UserId,
		Service:   VK_SERVICE_NAME,
	}
	return resUser
}

// Vk authorization service callback handle.
//
// Parameters:
//   - w response writter
//   - r http request
func (service VkAuthService) vkAuthCallbackHandle(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get(STATE_NAME)
	if state == "" {
		err := errors.New("get vk oauth callback without state")
		service.ProcessError(err, w, r)
		return
	}
	err := VerifyCookieValue(r, STATE_COOKIE_NAME, state)
	if err != nil {
		service.ProcessError(err, w, r)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		err = errors.New("get vk outh callback without code")
		service.ProcessError(err, w, r)
		return
	}
	deviceId := r.URL.Query().Get("device_id")
	if code == "" {
		err = errors.New("get vk outh callback without device id")
		service.ProcessError(err, w, r)
		return
	}
	verifier, err := r.Cookie(VERIFIER_COOKIE_NAME)
	if err != nil {
		service.ProcessError(err, w, r)
		return
	}
	// Vk also send deviceId. Now we don't need it
	token, err := service.vkLoginConfig.Exchange(r.Context(), code,
		oauth2.SetAuthURLParam("code_verifier", verifier.Value),
		oauth2.SetAuthURLParam("device_id", deviceId))
	if err != nil {
		service.ProcessError(err, w, r)
	}
	user, err := service.getUserDataFromVk(token)
	if err != nil {
		service.ProcessError(err, w, r)
	}
	vkUser := vkToAuthUser(user)
	err = service.ProcessSuccess(vkUser, w, r)
	if err != nil {
	}
}

// Get Vk user data by received token.
//
// Parameters:
//   - token token received by Google
//
// Returns:
//
//	received data or error
func (service VkAuthService) getUserDataFromVk(token *oauth2.Token) (VkUser, error) {
	data := url.Values{}
	data.Set(ACCESS_TOKEN_KEY, token.AccessToken)
	data.Set(CLIENT_ID_KEY, service.vkLoginConfig.ClientID)
	vkData := VkData{}
	err := SendUrlEncodedReceiveJson(VK_GET_USER_METHOD, VK_USER_PROFILE_DATA_URL, data, &vkData)
	if err != nil {
		return VkUser{}, err
	}
	if vkData.Error != "" {
		return VkUser{}, errors.New(vkData.Error)
	}
	return vkData.User, err
}

// Registered Vk authorization service endpoints.
//
// Parameters:
//   - mux server mux
func (service VkAuthService) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET "+service.GetLoginEndpoint(service.GetServiceName()), service.vkAuthLoginHandle)
	mux.HandleFunc("GET "+service.GetCallbackEndpoint(service.GetServiceName()), service.vkAuthCallbackHandle)
}
