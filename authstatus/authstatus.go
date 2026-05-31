// Package authstatus evaluates plugin auth readiness without exposing secrets.
package authstatus

import (
	"context"
	"strings"

	"github.com/fluxplane/fluxplane-auth"
	"github.com/fluxplane/fluxplane-secret"
)

const (
	StatusConnected    = "connected"
	StatusNotConnected = "not_connected"
)

// Target is one plugin instance whose declared auth methods should be checked.
type Target struct {
	Plugin   string
	Instance string
	Methods  []auth.MethodSpec
}

// Status is a non-secret summary of one plugin instance's auth readiness.
type Status struct {
	Plugin    string        `json:"plugin"`
	Instance  string        `json:"instance,omitempty"`
	Status    string        `json:"status"`
	MethodID  string        `json:"method_id,omitempty"`
	Method    string        `json:"method,omitempty"`
	Connected bool          `json:"connected"`
	Message   string        `json:"message,omitempty"`
	Fields    []FieldStatus `json:"fields,omitempty"`
}

// FieldStatus is non-secret presence information for a setup field.
type FieldStatus struct {
	Name string `json:"name"`
	Set  bool   `json:"set"`
}

// Evaluate returns the first locally resolvable auth method for target.
func Evaluate(ctx context.Context, resolver secret.Resolver, target Target) Status {
	plugin := strings.TrimSpace(target.Plugin)
	instance := strings.TrimSpace(target.Instance)
	if instance == "" {
		instance = plugin
	}
	status := Status{
		Plugin:   plugin,
		Instance: instance,
		Status:   StatusNotConnected,
	}
	for _, method := range target.Methods {
		configured, fields := methodConfigured(ctx, resolver, plugin, instance, method)
		if configured {
			status.Status = StatusConnected
			status.Connected = true
			status.MethodID = strings.TrimSpace(method.Name)
			status.Method = FriendlyMethodName(method)
			status.Fields = fields
			return status
		}
		if status.Method == "" && anyFieldSet(fields) {
			status.MethodID = strings.TrimSpace(method.Name)
			status.Method = FriendlyMethodName(method)
			status.Fields = fields
		}
	}
	if len(target.Methods) == 0 {
		status.Message = "no auth methods declared"
	}
	return status
}

// FriendlyMethodName returns the compact method label used in status summaries.
func FriendlyMethodName(method auth.MethodSpec) string {
	name := strings.ToLower(strings.TrimSpace(method.Name))
	switch name {
	case "personal_access_token", "personal-access-token", "api_token", "api-token", "bearer":
		return "token"
	default:
		return name
	}
}

func methodConfigured(ctx context.Context, resolver secret.Resolver, plugin, instance string, method auth.MethodSpec) (bool, []FieldStatus) {
	if resolver == nil {
		return false, nil
	}
	if method.Method == auth.MethodStored && len(method.SetupFields) > 0 {
		return setupFieldsConfigured(ctx, resolver, plugin, instance, method.SetupFields)
	}
	if len(method.SetupFields) > 0 {
		fieldsConfigured, fields := setupFieldsConfigured(ctx, resolver, plugin, instance, method.SetupFields)
		for _, candidate := range refsForMethod(method) {
			if secretConfigured(ctx, resolver, candidate) {
				return fieldsConfigured, fields
			}
		}
		return false, fields
	}
	for _, candidate := range refsForMethod(method) {
		if secretConfigured(ctx, resolver, candidate) {
			return true, nil
		}
	}
	return false, nil
}

func setupFieldsConfigured(ctx context.Context, resolver secret.Resolver, plugin, instance string, fields []auth.FieldSpec) (bool, []FieldStatus) {
	configured := map[string]bool{}
	statuses := make([]FieldStatus, 0, len(fields))
	anySet := false
	for _, field := range fields {
		name := strings.TrimSpace(string(field.Slot))
		if name == "" {
			continue
		}
		set := secretConfigured(ctx, resolver, secret.Plugin(plugin, instance, secret.Slot(name))) || envConfigured(ctx, resolver, field.Env)
		configured[name] = set
		anySet = anySet || set
		statuses = append(statuses, FieldStatus{Name: name, Set: set})
	}
	for _, field := range fields {
		name := strings.TrimSpace(string(field.Slot))
		if field.Required && !configured[name] {
			return false, statuses
		}
	}
	groups := requiredGroups(fields)
	for _, names := range groups {
		ok := false
		for _, name := range names {
			if configured[name] {
				ok = true
				break
			}
		}
		if !ok {
			return false, statuses
		}
	}
	return anySet, statuses
}

func refsForMethod(method auth.MethodSpec) []secret.Ref {
	switch method.Method {
	case auth.MethodEnv:
		return envRefs(method.Env)
	case auth.MethodOAuth2AuthCode, auth.MethodStored:
		ref := method.Secret.Normalize()
		if ref.ResourceName() == "" {
			return nil
		}
		return []secret.Ref{ref}
	default:
		return nil
	}
}

func envConfigured(ctx context.Context, resolver secret.Resolver, spec auth.EnvSpec) bool {
	for _, ref := range envRefs(spec) {
		if secretConfigured(ctx, resolver, ref) {
			return true
		}
	}
	return false
}

func envRefs(spec auth.EnvSpec) []secret.Ref {
	names := append([]string{spec.Name}, spec.Aliases...)
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

func secretConfigured(ctx context.Context, resolver secret.Resolver, ref secret.Ref) bool {
	material, ok, err := resolver.ResolveSecret(ctx, ref)
	return err == nil && ok && strings.TrimSpace(string(material.Value)) != ""
}

func anyFieldSet(fields []FieldStatus) bool {
	for _, field := range fields {
		if field.Set {
			return true
		}
	}
	return false
}

func requiredGroups(fields []auth.FieldSpec) map[string][]string {
	groups := map[string][]string{}
	for _, field := range fields {
		group := strings.TrimSpace(field.RequiredGroup)
		name := strings.TrimSpace(string(field.Slot))
		if group == "" || name == "" {
			continue
		}
		groups[group] = append(groups[group], name)
	}
	return groups
}
