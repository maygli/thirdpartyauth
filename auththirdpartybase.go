package auththirdparty

import (
	"fmt"
	"net/http"
)

const (
	// Default login endpoint template
	LOGIN_END_POINT_TEMPLATE = "/auth/%s/login"
	// Default callback endpoint template
	CALLBACK_END_POINT_TEMPLATE = "/auth/%s/callback"
)

// Authorization service interface
type IAuthThirdPartyService interface {
	// Register authorization endpoints
	// Parameters:
	//   - mux server mux
	RegisterHandlers(mux *http.ServeMux)

	// Return service name (for example 'google')
	// Returns:
	//   - service name
	GetServiceName() string
}

// Base structure for third party authentification service
type AuthThirdPartyBase struct {
	// Custom login endpoint. If empty login endpoint will be /auth/<service name>/login
	// for example (/auth/google/login)
	LoginEndPoint string
	// Custom callback endpoint. If empty callback endpoint will be /auth/<service name>/callback
	// for example (/auth/google/callabck)
	CallbackEndPoint string
	// Auth processor
	AuthProcessor CompleteAuthProcessor
}

// Return login endpoint. If service.LoginEndPoint is defined it will be returned.
// Otherwise default login endpoint will be returned (like /auth/google/login)
// Parameters:
//   - serviceName service name (for example 'google')
//
// Returns:
//   - login endpoint
func (service AuthThirdPartyBase) GetLoginEndpoint(serviceName string) string {
	if service.LoginEndPoint != "" {
		return service.LoginEndPoint
	}
	return fmt.Sprintf(LOGIN_END_POINT_TEMPLATE, serviceName)
}

// Return callback endpoint. If service.CallabckEndPoint is defined it will be returned.
// Otherwise default callback endpoint will be returned (like /auth/google/callback)
// Parameters:
//   - serviceName service name (for example 'google')
//
// Returns:
//   - callback endpoint
func (service AuthThirdPartyBase) GetCallbackEndpoint(serviceName string) string {
	if service.CallbackEndPoint != "" {
		return service.CallbackEndPoint
	}
	return fmt.Sprintf(CALLBACK_END_POINT_TEMPLATE, serviceName)
}

// This function called in case of error has been occured during authorization process.
// If processor is defined ProcessError function of processor will be called. If processor
// is not defined just redirected to root
// Parameters:
//   - err
//   - w response writter
//   - h http request
func (service AuthThirdPartyBase) ProcessError(err error, w http.ResponseWriter, r *http.Request) {
	if service.AuthProcessor != nil {
		service.AuthProcessor.ProcessError(err, w, r)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// This function called in case of authorization process is success.
// If processor is defined ProcessSuccess function of processor will be called. If processor
// is not defined just redirected to root
// Parameters:
//   - err
//   - w response writter
//   - h http request
func (service AuthThirdPartyBase) ProcessSuccess(user AuthThirdPartyUser, w http.ResponseWriter, r *http.Request) error {
	var err error = nil
	if service.AuthProcessor != nil {
		err := service.AuthProcessor.ProcessSuceess(user, w, r)
		if err == nil {
			return err
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return err
}
