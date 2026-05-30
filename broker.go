package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fluxplane/fluxplane-policy"
	"github.com/fluxplane/fluxplane-policy/policyauth"
	"github.com/fluxplane/fluxplane-secret"
)

// Scope ties opaque secret handles to one session/turn.
type Scope struct {
	Session string
	Turn    string
}

type scopeContextKey struct{}

// ContextWithScope stores secret handle scope on ctx.
func ContextWithScope(ctx context.Context, scope Scope) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, scopeContextKey{}, scope)
}

// ScopeFromContext returns the handle scope carried by ctx.
func ScopeFromContext(ctx context.Context) Scope {
	if ctx == nil {
		return Scope{}
	}
	scope, _ := ctx.Value(scopeContextKey{}).(Scope)
	return scope
}

// Broker authorizes secret use and mints scoped opaque placeholders.
type Broker struct {
	resolver secret.Resolver
	now      func() time.Time
	ttl      time.Duration
	mu       sync.Mutex
	handles  map[string]handleRecord
}

type handleRecord struct {
	Scope    Scope
	Ref      secret.Ref
	Material secret.Material
	Expires  time.Time
}

// Resolution is resolved credential material plus the method that supplied it.
type Resolution struct {
	Ref      secret.Ref
	Method   MethodSpec
	Material secret.Material
}

// NewBroker returns a broker backed by resolver.
func NewBroker(resolver secret.Resolver) *Broker {
	return &Broker{
		resolver: resolver,
		now:      time.Now,
		ttl:      time.Hour,
		handles:  map[string]handleRecord{},
	}
}

// WithTTL sets handle lifetime.
func (b *Broker) WithTTL(ttl time.Duration) *Broker {
	if ttl > 0 {
		b.ttl = ttl
	}
	return b
}

// Use resolves a secret after checking secret.use authorization.
func (b *Broker) Use(ctx context.Context, ref secret.Ref) (secret.Material, bool, error) {
	if b == nil || b.resolver == nil {
		return secret.Material{}, false, fmt.Errorf("secret broker resolver is nil")
	}
	ref = ref.Normalize()
	if err := authorizeSecretUse(ctx, ref); err != nil {
		return secret.Material{}, false, err
	}
	return b.resolver.ResolveSecret(ctx, ref)
}

// UseFirst resolves the first available ref after checking secret.use for that
// concrete ref. Missing candidates do not require authorization.
func (b *Broker) UseFirst(ctx context.Context, refs ...secret.Ref) (secret.Ref, secret.Material, bool, error) {
	if b == nil || b.resolver == nil {
		return secret.Ref{}, secret.Material{}, false, fmt.Errorf("secret broker resolver is nil")
	}
	for _, ref := range refs {
		ref = ref.Normalize()
		probe, ok, err := b.resolver.ResolveSecret(ctx, ref)
		if err != nil {
			return secret.Ref{}, secret.Material{}, false, err
		}
		if !ok {
			continue
		}
		if err := authorizeSecretUse(ctx, ref); err != nil {
			return ref, secret.Material{}, false, err
		}
		return ref, probe, true, nil
	}
	return secret.Ref{}, secret.Material{}, false, nil
}

// UseAvailable resolves the first configured auth method that has material
// after checking secret.use on the logical plugin secret.
func (b *Broker) UseAvailable(ctx context.Context, req Request) (Resolution, bool, error) {
	if b == nil || b.resolver == nil {
		return Resolution{}, false, fmt.Errorf("secret broker resolver is nil")
	}
	req = req.Normalize()
	logical := req.SecretRef()
	if logical.ResourceName() == "" {
		return Resolution{}, false, fmt.Errorf("secret auth request is incomplete")
	}
	if err := authorizeSecretUse(ctx, logical); err != nil {
		return Resolution{}, false, err
	}
	for _, method := range req.Methods {
		if err := ValidateMethod(method); err != nil {
			return Resolution{}, false, err
		}
		for _, ref := range refsForMethod(method) {
			material, found, err := b.resolver.ResolveSecret(ctx, ref)
			if found && method.Kind != "" {
				material.Kind = method.Kind
			}
			if err != nil || found {
				return Resolution{Ref: ref, Method: method, Material: material}, found, err
			}
		}
	}
	return Resolution{}, false, nil
}

// Mint returns a model-visible placeholder for a resolved secret.
func (b *Broker) Mint(ctx context.Context, ref secret.Ref) (secret.Placeholder, bool, error) {
	material, ok, err := b.Use(ctx, ref)
	if err != nil || !ok {
		return "", ok, err
	}
	handle, err := randomHandle()
	if err != nil {
		return "", false, err
	}
	record := handleRecord{
		Scope:    ScopeFromContext(ctx),
		Ref:      ref.Normalize(),
		Material: material,
		Expires:  b.now().Add(b.ttl),
	}
	b.mu.Lock()
	b.handles[handle] = record
	b.mu.Unlock()
	return secret.PlaceholderFor(handle), true, nil
}

// ResolveHandle resolves a previously minted handle in the same scope.
func (b *Broker) ResolveHandle(ctx context.Context, handle string) (secret.Material, bool, error) {
	if b == nil {
		return secret.Material{}, false, fmt.Errorf("secret broker is nil")
	}
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return secret.Material{}, false, fmt.Errorf("secret handle is empty")
	}
	b.mu.Lock()
	record, ok := b.handles[handle]
	if ok && !record.Expires.IsZero() && !b.now().Before(record.Expires) {
		delete(b.handles, handle)
		ok = false
	}
	b.mu.Unlock()
	if !ok {
		return secret.Material{}, false, nil
	}
	if !sameScope(record.Scope, ScopeFromContext(ctx)) {
		return secret.Material{}, false, fmt.Errorf("secret handle scope mismatch")
	}
	if err := authorizeSecretUse(ctx, record.Ref); err != nil {
		return secret.Material{}, false, err
	}
	return record.Material, true, nil
}

func refsForMethod(method MethodSpec) []secret.Ref {
	switch method.Method {
	case MethodEnv:
		if strings.TrimSpace(method.Env.Name) == "" {
			return envRefs(method.Env.Aliases)
		}
		return []secret.Ref{secret.Env(method.Env.Name)}
	case MethodOAuth2AuthCode, MethodOAuth2DeviceCode, MethodStored:
		ref := method.Secret.Normalize()
		if ref.ResourceName() == "" {
			return nil
		}
		return []secret.Ref{ref}
	default:
		return nil
	}
}

func envRefs(names []string) []secret.Ref {
	refs := make([]secret.Ref, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		refs = append(refs, secret.Env(name))
	}
	return refs
}

func authorizeSecretUse(ctx context.Context, ref secret.Ref) error {
	authCtx, ok := policyauth.AuthorizationFromContext(ctx)
	if !ok || authCtx.Policy.IsZero() {
		return nil
	}
	req := policy.AuthorizationRequest{
		Subjects: authCtx.Subjects,
		Trust:    authCtx.Trust,
		Resource: policy.ResourceRef{Kind: policy.ResourceSecret, Name: ref.ResourceName()},
		Action:   policy.ActionSecretUse,
	}
	evaluation := policy.EvaluateAuthorization(authCtx.Policy, req)
	policyauth.EmitAuthorizationDecision(ctx, authCtx, req, evaluation)
	if evaluation.Decision == policy.DecisionAllow {
		return nil
	}
	return fmt.Errorf("authorization_%s: %s secret:%s: %s", evaluation.Decision, policy.ActionSecretUse, ref.ResourceName(), evaluation.Reason)
}

func randomHandle() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func sameScope(a, b Scope) bool {
	return a.Session == b.Session && a.Turn == b.Turn
}
