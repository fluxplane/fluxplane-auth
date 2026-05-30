package auth

// ProviderRef identifies an authentication provider or plugin.
type ProviderRef string

// ConnectionRef identifies one configured authentication connection.
type ConnectionRef string

// CredentialRef identifies credential material without exposing its value.
type CredentialRef string

// SchemeType identifies a supported authentication scheme.
type SchemeType string

const (
	SchemeAPIKey              SchemeType = "api_key"
	SchemeBearerToken         SchemeType = "bearer_token"
	SchemeBasic               SchemeType = "basic"
	SchemeOAuth2AuthCode      SchemeType = "oauth2_authorization_code"
	SchemeOAuth2DeviceCode    SchemeType = "oauth2_device_code"
	SchemePersonalAccessToken SchemeType = "personal_access_token"
	SchemeCustom              SchemeType = "custom"
)

// FieldKind describes the shape of one credential field.
type FieldKind string

const (
	FieldString   FieldKind = "string"
	FieldPassword FieldKind = "password"
	FieldToken    FieldKind = "token"
	FieldURL      FieldKind = "url"
	FieldJSON     FieldKind = "json"
)

// FieldSpec describes one credential field required by an auth scheme.
type FieldSpec struct {
	Name        string            `json:"name"`
	Kind        FieldKind         `json:"kind,omitempty"`
	Description string            `json:"description,omitempty"`
	Required    bool              `json:"required,omitempty"`
	Sensitive   bool              `json:"sensitive,omitempty"`
	Env         []string          `json:"env,omitempty"`
	Purposes    []string          `json:"purposes,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SchemeSpec declares one way a provider can authenticate.
type SchemeSpec struct {
	Type        SchemeType        `json:"type"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Fields      []FieldSpec       `json:"fields,omitempty"`
	Scopes      []string          `json:"scopes,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ProviderSpec declares authentication options for a provider or plugin.
type ProviderSpec struct {
	Ref           ProviderRef       `json:"ref"`
	DisplayName   string            `json:"display_name,omitempty"`
	Description   string            `json:"description,omitempty"`
	Schemes       []SchemeSpec      `json:"schemes,omitempty"`
	DefaultScheme SchemeType        `json:"default_scheme,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Status describes the current state of an auth connection.
type Status string

const (
	StatusUnknown   Status = "unknown"
	StatusConnected Status = "connected"
	StatusMissing   Status = "missing"
	StatusExpired   Status = "expired"
	StatusInvalid   Status = "invalid"
)

// ConnectionStatus reports the host-known status for one auth connection.
type ConnectionStatus struct {
	Ref         ConnectionRef     `json:"ref,omitempty"`
	Provider    ProviderRef       `json:"provider,omitempty"`
	Scheme      SchemeType        `json:"scheme,omitempty"`
	Status      Status            `json:"status"`
	Message     string            `json:"message,omitempty"`
	Diagnostics []string          `json:"diagnostics,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
