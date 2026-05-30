package auth

import (
	"strings"
	"testing"

	"github.com/fluxplane/fluxplane-secret"
)

func TestValidateMethodTrimsAndAcceptsStoredSetupFields(t *testing.T) {
	err := ValidateMethod(MethodSpec{
		Name:   " token ",
		Method: " stored ",
		SetupFields: []FieldSpec{{
			Slot:     " access_token ",
			Required: true,
		}},
	})
	if err != nil {
		t.Fatalf("ValidateMethod returned error: %v", err)
	}
}

func TestValidateProviderRejectsDuplicateMethods(t *testing.T) {
	err := ValidateProvider(ProviderSpec{
		Ref: "github",
		Methods: []MethodSpec{
			{Name: "token", Method: MethodStored, Secret: secret.Plugin("github", "", "access_token")},
			{Name: " token ", Method: MethodStored, Secret: secret.Plugin("github", "", "api_key")},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "declared more than once") {
		t.Fatalf("expected duplicate method error, got %v", err)
	}
}

func TestValidateProviderRejectsMissingDefault(t *testing.T) {
	err := ValidateProvider(ProviderSpec{
		Ref:           "github",
		DefaultMethod: "oauth",
		Methods: []MethodSpec{
			{Name: "token", Method: MethodStored, Secret: secret.Plugin("github", "", "access_token")},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "default_method") {
		t.Fatalf("expected default_method error, got %v", err)
	}
}

func TestValidateMethodRejectsDuplicateSetupFields(t *testing.T) {
	err := ValidateMethod(MethodSpec{
		Name:   "token",
		Method: MethodStored,
		SetupFields: []FieldSpec{
			{Slot: "access_token"},
			{Slot: " access_token "},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "setup field") {
		t.Fatalf("expected duplicate setup field error, got %v", err)
	}
}

func TestTargetRefNormalizeAndEmpty(t *testing.T) {
	if !(TargetRef{}).Empty() {
		t.Fatal("zero target should be empty")
	}
	ref := TargetRef{Provider: " github ", Instance: " work "}.Normalize()
	if ref.Provider != "github" || ref.Instance != "work" || ref.Empty() {
		t.Fatalf("unexpected normalized target: %#v", ref)
	}
}
