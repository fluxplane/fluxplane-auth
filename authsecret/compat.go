package authsecret

import (
	"context"
	"strings"

	"github.com/fluxplane/fluxplane-auth"
	"github.com/fluxplane/fluxplane-secret"
)

// Secret and auth compatibility aliases for migrated consumers that previously
// imported fluxplane-core/core/secret or fluxplane-core/runtime/secret.
type Scheme = secret.Scheme
type Kind = secret.Kind
type Slot = secret.Slot
type Use = secret.Use
type StoreRef = secret.StoreRef
type Ref = secret.Ref
type Material = secret.Material
type Placeholder = secret.Placeholder
type Resolver = secret.Resolver
type ResolverFunc = secret.ResolverFunc
type EnvResolver = secret.EnvResolver
type ChainResolver = secret.ChainResolver
type Registry = secret.Registry

type Broker = auth.Broker
type Scope = auth.Scope
type Resolution = auth.Resolution

type AuthRequest = auth.Request
type AuthMethodKind = auth.Method
type AuthMethodSpec = auth.MethodSpec
type EnvSpec = auth.EnvSpec
type HeaderSpec = auth.HeaderSpec
type OAuth2Spec = auth.OAuth2Spec
type SetupFieldSpec = auth.FieldSpec

const (
	SchemeEnv        = secret.SchemeEnv
	SchemePlugin     = secret.SchemePlugin
	SchemeKubernetes = secret.SchemeKubernetes

	KindAPIKey      = secret.KindAPIKey
	KindBearerToken = secret.KindBearerToken
	KindOAuth2Token = secret.KindOAuth2Token
	KindBasic       = secret.KindBasic
	KindPKI         = secret.KindPKI

	UseAuthToken = secret.UseAuthToken
	UseAPIKey    = secret.UseAPIKey
	UsePassword  = secret.UsePassword
	UseTLS       = secret.UseTLS
	UseSigning   = secret.UseSigning

	AuthMethodEnv    AuthMethodKind = auth.MethodEnv
	AuthMethodOAuth2 AuthMethodKind = auth.MethodOAuth2AuthCode
	AuthMethodStored AuthMethodKind = auth.MethodStored
)

func NewBroker(resolver Resolver) *Broker { return auth.NewBroker(resolver) }
func ContextWithScope(ctx context.Context, scope Scope) context.Context {
	return auth.ContextWithScope(ctx, scope)
}
func ScopeFromContext(ctx context.Context) Scope  { return auth.ScopeFromContext(ctx) }
func NewRegistry(resolvers ...Resolver) *Registry { return secret.NewRegistry(resolvers...) }
func FromSharedRef(ref secret.Ref) Ref            { return ref.Normalize() }
func Env(name string) Ref                         { return secret.Env(name) }
func EnvWildcard() Ref                            { return secret.EnvWildcard() }
func Plugin(plugin, instance, name string) Ref {
	return secret.Plugin(plugin, instance, secret.Slot(name))
}
func Kubernetes(namespace, secretName, key string) Ref {
	return secret.Kubernetes(namespace, secretName, secret.Slot(key))
}
func ParseRef(value string) Ref                     { return secret.ParseRef(value) }
func FromSharedMaterial(m secret.Material) Material { return m }
func PlaceholderFor(handle string) Placeholder      { return secret.PlaceholderFor(handle) }
func ParsePlaceholder(value string) (string, bool)  { return secret.ParsePlaceholder(value) }
func ReplacePlaceholders(value string, replace func(handle string) (string, error)) (string, error) {
	return secret.ReplacePlaceholders(value, replace)
}
func RedactPlaceholders(value string) string       { return secret.RedactPlaceholders(value) }
func ValidateAuthMethod(spec AuthMethodSpec) error { return auth.ValidateMethod(spec) }
func SetupFieldName(spec SetupFieldSpec) string    { return strings.TrimSpace(string(spec.Slot)) }
func WireMaterialFromMaterial(m Material) secret.WireMaterial {
	return secret.WireMaterialFromMaterial(m)
}
