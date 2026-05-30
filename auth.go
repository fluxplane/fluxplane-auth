package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/fluxplane/fluxplane-secret"
)

// ProviderRef identifies an authentication provider or plugin.
type ProviderRef string

// ConnectionRef identifies one configured authentication connection.
type ConnectionRef string

// TargetRef identifies the provider surface a connection authenticates.
type TargetRef struct {
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"`
	Instance string `json:"instance,omitempty" yaml:"instance,omitempty"`
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
}

// Normalize returns a trimmed target ref.
func (r TargetRef) Normalize() TargetRef {
	r.Provider = strings.TrimSpace(r.Provider)
	r.Instance = strings.TrimSpace(r.Instance)
	r.Endpoint = strings.TrimSpace(r.Endpoint)
	return r
}

// Empty reports whether the target has no identifying fields.
func (r TargetRef) Empty() bool {
	r = r.Normalize()
	return r.Provider == "" && r.Instance == "" && r.Endpoint == ""
}

// Scheme identifies the credential presentation scheme used against a provider.
type Scheme string

const (
	SchemeAPIKey              Scheme = "api_key"
	SchemeBearerToken         Scheme = "bearer_token"
	SchemeBasic               Scheme = "basic"
	SchemeOAuth2              Scheme = "oauth2"
	SchemePersonalAccessToken Scheme = "personal_access_token"
	SchemeCustom              Scheme = "custom"
)

// Method identifies how credential material may be obtained or configured.
type Method string

const (
	MethodEnv              Method = "env"
	MethodStored           Method = "stored"
	MethodOAuth2AuthCode   Method = "oauth2_authorization_code"
	MethodOAuth2DeviceCode Method = "oauth2_device_code"
	MethodHostManaged      Method = "host_managed"
	MethodManual           Method = "manual"
)

// FieldKind describes the shape of one setup or credential field.
type FieldKind string

const (
	FieldString   FieldKind = "string"
	FieldPassword FieldKind = "password"
	FieldToken    FieldKind = "token"
	FieldURL      FieldKind = "url"
	FieldJSON     FieldKind = "json"
)

// EnvSpec describes environment variable suggestions for a field or method.
type EnvSpec struct {
	Name    string   `json:"name,omitempty" yaml:"name,omitempty"`
	Aliases []string `json:"aliases,omitempty" yaml:"aliases,omitempty"`
}

// FieldSpec describes one setup input or credential slot required by an auth
// method. Slot is the addressable credential name; Uses describes broad
// semantics.
type FieldSpec struct {
	Slot          secret.Slot       `json:"slot" yaml:"slot"`
	Kind          FieldKind         `json:"kind,omitempty" yaml:"kind,omitempty"`
	DisplayName   string            `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	Description   string            `json:"description,omitempty" yaml:"description,omitempty"`
	Required      bool              `json:"required,omitempty" yaml:"required,omitempty"`
	RequiredGroup string            `json:"required_group,omitempty" yaml:"required_group,omitempty"`
	Sensitive     bool              `json:"sensitive,omitempty" yaml:"sensitive,omitempty"`
	Env           EnvSpec           `json:"env,omitempty" yaml:"env,omitempty"`
	Uses          []secret.Use      `json:"uses,omitempty" yaml:"uses,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// Normalize returns a field spec with trimmed scalar fields.
func (s FieldSpec) Normalize() FieldSpec {
	s.Slot = secret.Slot(strings.TrimSpace(string(s.Slot)))
	s.Kind = FieldKind(strings.TrimSpace(string(s.Kind)))
	s.DisplayName = strings.TrimSpace(s.DisplayName)
	s.Description = strings.TrimSpace(s.Description)
	s.RequiredGroup = strings.TrimSpace(s.RequiredGroup)
	s.Env.Name = strings.TrimSpace(s.Env.Name)
	return s
}

// HeaderSpec describes where an API key or token is applied on outbound HTTP.
type HeaderSpec struct {
	Name   string `json:"name,omitempty" yaml:"name,omitempty"`
	Scheme string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
}

// OAuth2Spec describes OAuth2 endpoints and requested authorization scopes.
type OAuth2Spec struct {
	AuthorizeURL string            `json:"authorize_url,omitempty" yaml:"authorize_url,omitempty"`
	TokenURL     string            `json:"token_url,omitempty" yaml:"token_url,omitempty"`
	RefreshURL   string            `json:"refresh_url,omitempty" yaml:"refresh_url,omitempty"`
	Scopes       []string          `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	ExtraParams  map[string]string `json:"extra_params,omitempty" yaml:"extra_params,omitempty"`
}

// MethodSpec declares one way a provider can obtain usable credential material.
type MethodSpec struct {
	Name        string            `json:"name" yaml:"name"`
	Method      Method            `json:"method" yaml:"method"`
	Scheme      Scheme            `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Kind        secret.Kind       `json:"kind,omitempty" yaml:"kind,omitempty"`
	DisplayName string            `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Secret      secret.Ref        `json:"secret,omitempty" yaml:"secret,omitempty"`
	Env         EnvSpec           `json:"env,omitempty" yaml:"env,omitempty"`
	Header      HeaderSpec        `json:"header,omitempty" yaml:"header,omitempty"`
	OAuth2      OAuth2Spec        `json:"oauth2,omitempty" yaml:"oauth2,omitempty"`
	SetupFields []FieldSpec       `json:"setup_fields,omitempty" yaml:"setup_fields,omitempty"`
	Scopes      []string          `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Products    []string          `json:"products,omitempty" yaml:"products,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// Normalize returns a method spec with trimmed scalar fields and normalized refs.
func (s MethodSpec) Normalize() MethodSpec {
	s.Name = strings.TrimSpace(s.Name)
	s.Method = Method(strings.TrimSpace(string(s.Method)))
	s.Scheme = Scheme(strings.TrimSpace(string(s.Scheme)))
	s.Kind = secret.Kind(strings.TrimSpace(string(s.Kind)))
	s.DisplayName = strings.TrimSpace(s.DisplayName)
	s.Description = strings.TrimSpace(s.Description)
	s.Secret = s.Secret.Normalize()
	s.Env.Name = strings.TrimSpace(s.Env.Name)
	s.Header.Name = strings.TrimSpace(s.Header.Name)
	s.Header.Scheme = strings.TrimSpace(s.Header.Scheme)
	s.OAuth2.AuthorizeURL = strings.TrimSpace(s.OAuth2.AuthorizeURL)
	s.OAuth2.TokenURL = strings.TrimSpace(s.OAuth2.TokenURL)
	s.OAuth2.RefreshURL = strings.TrimSpace(s.OAuth2.RefreshURL)
	for i := range s.SetupFields {
		s.SetupFields[i] = s.SetupFields[i].Normalize()
	}
	return s
}

// ProviderSpec declares authentication options for a provider or plugin.
type ProviderSpec struct {
	Ref           ProviderRef       `json:"ref" yaml:"ref"`
	DisplayName   string            `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	Description   string            `json:"description,omitempty" yaml:"description,omitempty"`
	Methods       []MethodSpec      `json:"methods,omitempty" yaml:"methods,omitempty"`
	DefaultMethod string            `json:"default_method,omitempty" yaml:"default_method,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// Material contains non-model-visible auth material selected by an auth method.
type Material struct {
	Method string                     `json:"method,omitempty" yaml:"method,omitempty"`
	Values map[secret.Slot][]byte     `json:"-" yaml:"-"`
	Refs   map[secret.Slot]secret.Ref `json:"refs,omitempty" yaml:"refs,omitempty"`
}

// WireMaterial is a trusted host/plugin-process transport DTO. It is not safe
// for model-visible surfaces or logs.
type WireMaterial struct {
	Method string                     `json:"method,omitempty" yaml:"method,omitempty"`
	Values map[secret.Slot]string     `json:"values,omitempty" yaml:"values,omitempty"`
	Refs   map[secret.Slot]secret.Ref `json:"refs,omitempty" yaml:"refs,omitempty"`
}

// HTTPRequest describes which credential slots a host should resolve for an
// authenticated HTTP call.
type HTTPRequest struct {
	BearerTokenSlot secret.Slot            `json:"bearer_token_slot,omitempty" yaml:"bearer_token_slot,omitempty"`
	UsernameSlot    secret.Slot            `json:"username_slot,omitempty" yaml:"username_slot,omitempty"`
	PasswordSlot    secret.Slot            `json:"password_slot,omitempty" yaml:"password_slot,omitempty"`
	HeaderSlots     map[string]secret.Slot `json:"header_slots,omitempty" yaml:"header_slots,omitempty"`
}

// Status describes the current state of an auth connection.
type Status string

const (
	StatusUnknown      Status = "unknown"
	StatusConnected    Status = "connected"
	StatusNotConnected Status = "not_connected"
	StatusPartial      Status = "partial"
	StatusMissing      Status = "missing"
	StatusExpired      Status = "expired"
	StatusInvalid      Status = "invalid"
)

// FieldStatus is non-secret presence information for one credential slot.
type FieldStatus struct {
	Slot     secret.Slot `json:"slot" yaml:"slot"`
	Set      bool        `json:"set" yaml:"set"`
	Required bool        `json:"required,omitempty" yaml:"required,omitempty"`
}

// ConnectionStatus reports the host-known status for one auth connection.
type ConnectionStatus struct {
	Ref         ConnectionRef     `json:"ref,omitempty" yaml:"ref,omitempty"`
	Target      TargetRef         `json:"target,omitempty" yaml:"target,omitempty"`
	Provider    ProviderRef       `json:"provider,omitempty" yaml:"provider,omitempty"`
	Method      string            `json:"method,omitempty" yaml:"method,omitempty"`
	Scheme      Scheme            `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Status      Status            `json:"status" yaml:"status"`
	Fields      []FieldStatus     `json:"fields,omitempty" yaml:"fields,omitempty"`
	Message     string            `json:"message,omitempty" yaml:"message,omitempty"`
	Diagnostics []string          `json:"diagnostics,omitempty" yaml:"diagnostics,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// TestRequest asks a provider or plugin to verify a configured auth connection.
type TestRequest struct {
	Provider  ProviderRef       `json:"provider,omitempty" yaml:"provider,omitempty"`
	Ref       ConnectionRef     `json:"ref,omitempty" yaml:"ref,omitempty"`
	Target    TargetRef         `json:"target,omitempty" yaml:"target,omitempty"`
	Method    string            `json:"method,omitempty" yaml:"method,omitempty"`
	Slots     []secret.Slot     `json:"slots,omitempty" yaml:"slots,omitempty"`
	Selectors []secret.Selector `json:"selectors,omitempty" yaml:"selectors,omitempty"`
}

// TestStatus is the result state for one auth test check.
type TestStatus string

const (
	TestPassed  TestStatus = "passed"
	TestFailed  TestStatus = "failed"
	TestSkipped TestStatus = "skipped"
)

// TestReport reports one auth connectivity or capability check.
type TestReport struct {
	Method      string            `json:"method,omitempty" yaml:"method,omitempty"`
	Check       string            `json:"check,omitempty" yaml:"check,omitempty"`
	Status      TestStatus        `json:"status" yaml:"status"`
	Message     string            `json:"message,omitempty" yaml:"message,omitempty"`
	Diagnostics []string          `json:"diagnostics,omitempty" yaml:"diagnostics,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// MethodProvider provides auth method declarations for a provider.
type MethodProvider interface {
	AuthMethods(context.Context, ProviderRef) ([]MethodSpec, error)
}

// StatusProvider reports non-secret auth status.
type StatusProvider interface {
	AuthStatus(context.Context, TargetRef) (ConnectionStatus, error)
}

// Tester performs live auth checks and streams non-secret reports.
type Tester interface {
	TestAuth(context.Context, TestRequest, chan<- TestReport) error
}

// ValidateProvider returns an error for incomplete provider auth specs.
func ValidateProvider(spec ProviderSpec) error {
	if strings.TrimSpace(string(spec.Ref)) == "" {
		return fmt.Errorf("auth provider ref is empty")
	}
	seen := map[string]bool{}
	for _, method := range spec.Methods {
		method = method.Normalize()
		if err := ValidateMethod(method); err != nil {
			return err
		}
		if seen[method.Name] {
			return fmt.Errorf("auth method %q is declared more than once", method.Name)
		}
		seen[method.Name] = true
	}
	if spec.DefaultMethod != "" && !seen[strings.TrimSpace(spec.DefaultMethod)] {
		return fmt.Errorf("auth default_method %q does not match a declared method", spec.DefaultMethod)
	}
	return nil
}

// ValidateMethod returns an error for incomplete method specs.
func ValidateMethod(spec MethodSpec) error {
	spec = spec.Normalize()
	if spec.Name == "" {
		return fmt.Errorf("auth method name is empty")
	}
	if spec.Method == "" {
		return fmt.Errorf("auth method %q method is empty", spec.Name)
	}
	if err := validateMethodResolution(spec); err != nil {
		return err
	}
	return validateSetupFields(spec.Name, spec.SetupFields)
}

func validateMethodResolution(spec MethodSpec) error {
	switch spec.Method {
	case MethodEnv:
		return validateEnvMethod(spec)
	case MethodStored:
		return validateStoredMethod(spec)
	case MethodOAuth2AuthCode, MethodOAuth2DeviceCode:
		return validateOAuth2Method(spec)
	case MethodHostManaged, MethodManual:
		return nil
	default:
		return fmt.Errorf("auth method %q method %q is unsupported", spec.Name, spec.Method)
	}
}

func validateEnvMethod(spec MethodSpec) error {
	if strings.TrimSpace(spec.Env.Name) == "" && len(nonEmpty(spec.Env.Aliases...)) == 0 {
		return fmt.Errorf("auth method %q env config is empty", spec.Name)
	}
	return nil
}

func validateStoredMethod(spec MethodSpec) error {
	if spec.Secret.Empty() && len(spec.SetupFields) == 0 {
		return fmt.Errorf("auth method %q secret ref or setup_fields is required", spec.Name)
	}
	return nil
}

func validateOAuth2Method(spec MethodSpec) error {
	if strings.TrimSpace(spec.OAuth2.TokenURL) == "" {
		return fmt.Errorf("auth method %q oauth2 token_url is empty", spec.Name)
	}
	if spec.Method == MethodOAuth2AuthCode && strings.TrimSpace(spec.OAuth2.AuthorizeURL) == "" {
		return fmt.Errorf("auth method %q oauth2 authorize_url is empty", spec.Name)
	}
	return nil
}

func validateSetupFields(methodName string, fields []FieldSpec) error {
	seen := map[secret.Slot]bool{}
	for _, field := range fields {
		field = field.Normalize()
		if field.Slot == "" {
			return fmt.Errorf("auth method %q setup field slot is empty", methodName)
		}
		if seen[field.Slot] {
			return fmt.Errorf("auth method %q setup field %q is declared more than once", methodName, field.Slot)
		}
		seen[field.Slot] = true
	}
	return nil
}

func nonEmpty(values ...string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}
