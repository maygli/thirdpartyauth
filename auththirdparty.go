package auththirdparty

import (
	"net/http"
	"slices"
)

// Structure represnt third party user data.
// This structure filled by service and pass
// to AuthProcessor sucess function in case
// of success authorization. Same fields can be
// empty. For example Telegram doesn't pass email.
type AuthThirdPartyUser struct {
	// First name
	FirstName string
	// Last name (can be empty)
	LastName string
	// User e-mail (cam be empty)
	Email string
	// Link to avatar. Can be empty
	Avatar string
	// User id (for exampla Telegram id)
	UserId string
	// Authorisation service name
	Service string
}

// Complete processor interface.
type CompleteAuthProcessor interface {
	// This function called in case of success authorization
	// Parameters:
	//   - user filled user structure
	//   - w response writter
	//   - h request
	//
	// Returns:
	//   - error in case of error
	ProcessSuceess(user any, w http.ResponseWriter, r *http.Request) error

	// This function called in case of error during authorization
	// Parameters:
	//   - error error
	//   - w response writter
	//   - h request
	//
	// Returns:
	//   - error in case of error
	ProcessError(err error, w http.ResponseWriter, r *http.Request) error
}

// Third party authentification configuration
// Contains configurations for third party services.
type ThirdPartyConfig struct {
	GoogleCfg   GoogleAuthConfigure   `json:"google"`
	TelegramCfg TelegramAuthConfigure `json:"telegram"`
	VkCfg       VkAuthConfigure       `json:"vk"`
	YandexCfg   YandexAuthConfigure   `json:"yandex"`
}

// Structure represents third party services
type AuthThirdPartyService struct {
	Services []IAuthThirdPartyService
}

// Return name based on user structure. In general it's
//
//	FirestName + " " + LastName (for example John Doe)
//
// Returns:
//   - name
func (user AuthThirdPartyUser) GetName() string {
	name := user.FirstName
	if name != "" && user.LastName != "" {
		name += " "
	}
	name += user.LastName
	return name
}

// Create third party service structure
// Parameters:
//   - config third party configuration structure
//   - processor structure implements CompleteAuthProcessor interface and
//     have two functions for processing success third party authorization
//     or error ducring authorization process
//   - serviceNamesList list of service names supported by module
//
// Returns:
//   - pointer to created third party authorization structure
func NewThirdPartyAuth(config *ThirdPartyConfig, processor CompleteAuthProcessor, serviceNamesList []string) *AuthThirdPartyService {
	services := AuthThirdPartyService{
		Services: make([]IAuthThirdPartyService, 0),
	}
	if slices.Contains(serviceNamesList, GOOGLE_SERVICE_NAME) {
		service := NewGoogleAuthService(config.GoogleCfg, processor)
		if service != nil {
			services.Services = append(services.Services, service)
		}
	}
	if slices.Contains(serviceNamesList, TELEGRAM_SERVICE_NAME) {
		service := NewTelegramAuthService(config.TelegramCfg, processor)
		if service != nil {
			services.Services = append(services.Services, service)
		}
	}
	if slices.Contains(serviceNamesList, VK_SERVICE_NAME) {
		service := NewVkAuthService(config.VkCfg, processor)
		if service != nil {
			services.Services = append(services.Services, service)
		}
	}
	if slices.Contains(serviceNamesList, YANDEX_SERVICE_NAME) {
		service := NewYandexAuthService(config.YandexCfg, processor)
		if service != nil {
			services.Services = append(services.Services, service)
		}
	}
	return &services
}

// Register third party authorization service endpoints
// Parameters:
//   - mux server mux to registry endpoints
func (service AuthThirdPartyService) RegisterHandlers(mux *http.ServeMux) {
	for _, serv := range service.Services {
		serv.RegisterHandlers(mux)
	}
}

// Returns all service names supported by module
// Returns:
//
//	slice of service names
func GetSupportedServiceNames() []string {
	return []string{GOOGLE_SERVICE_NAME, TELEGRAM_SERVICE_NAME, VK_SERVICE_NAME, YANDEX_SERVICE_NAME}
}
