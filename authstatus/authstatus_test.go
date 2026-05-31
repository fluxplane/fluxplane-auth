package authstatus

import (
	"context"
	"testing"

	"github.com/fluxplane/fluxplane-auth"
	sharedsecret "github.com/fluxplane/fluxplane-secret"
)

func TestEvaluateUsesRequiredGroupSetupField(t *testing.T) {
	store := sharedsecret.NewFileStore(t.TempDir())
	if err := store.SaveSecret(context.Background(), sharedsecret.StoredSecret{
		Ref:   sharedsecret.Plugin("slack", "work", sharedsecret.Slot("user_token")),
		Kind:  sharedsecret.KindBearerToken,
		Value: "slack-user-token",
	}); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	status := Evaluate(context.Background(), store, Target{
		Plugin:   "slack",
		Instance: "work",
		Methods: []auth.MethodSpec{{
			Name:   "token",
			Method: auth.MethodStored,
			Kind:   sharedsecret.KindBearerToken,
			SetupFields: []auth.FieldSpec{
				{Slot: "bot_token", RequiredGroup: "api_token"},
				{Slot: "user_token", RequiredGroup: "api_token"},
			},
		}},
	})
	if !status.Connected || status.Method != "token" {
		t.Fatalf("status = %#v", status)
	}
}

func TestEvaluateReportsPartialRequiredGroupFields(t *testing.T) {
	store := sharedsecret.NewFileStore(t.TempDir())
	for _, secret := range []sharedsecret.StoredSecret{
		{Ref: sharedsecret.Plugin("jira", "work", sharedsecret.Slot("email")), Kind: sharedsecret.KindBasic, Value: "user@example.invalid"},
		{Ref: sharedsecret.Plugin("jira", "work", sharedsecret.Slot("token")), Kind: sharedsecret.KindBasic, Value: "api-token"},
	} {
		if err := store.SaveSecret(context.Background(), secret); err != nil {
			t.Fatalf("SaveSecret: %v", err)
		}
	}
	status := Evaluate(context.Background(), store, Target{
		Plugin:   "jira",
		Instance: "work",
		Methods: []auth.MethodSpec{{
			Name:   "api_token",
			Method: auth.MethodStored,
			Kind:   sharedsecret.KindBasic,
			SetupFields: []auth.FieldSpec{
				{Slot: "email", Required: true},
				{Slot: "token", Required: true},
				{Slot: "cloud_id"},
				{Slot: "site_url", RequiredGroup: "site_locator"},
				{Slot: "base_url", RequiredGroup: "site_locator"},
			},
		}},
	})
	if status.Connected || status.Method != "token" {
		t.Fatalf("status = %#v, want partial token readiness", status)
	}
	got := map[string]bool{}
	for _, field := range status.Fields {
		got[field.Name] = field.Set
	}
	if !got["email"] || !got["token"] || got["cloud_id"] || got["site_url"] || got["base_url"] {
		t.Fatalf("fields = %#v", status.Fields)
	}
}

func TestEvaluateUsesEnvironmentAlias(t *testing.T) {
	env := fakeEnvironment{values: map[string]string{"GITLAB_TOKEN": "glpat-test"}}
	status := Evaluate(context.Background(), sharedsecret.EnvResolver{Environment: env}, Target{
		Plugin:   "gitlab",
		Instance: "gitlab",
		Methods: []auth.MethodSpec{{
			Name:   "personal_access_token",
			Method: auth.MethodEnv,
			Kind:   sharedsecret.KindAPIKey,
			Env:    auth.EnvSpec{Aliases: []string{"GITLAB_TOKEN"}},
		}},
	})
	if !status.Connected || status.Method != "token" {
		t.Fatalf("status = %#v", status)
	}
}

type fakeEnvironment struct {
	values map[string]string
}

func (e fakeEnvironment) Lookup(_ context.Context, key string) (string, bool, error) {
	value, ok := e.values[key]
	return value, ok, nil
}
