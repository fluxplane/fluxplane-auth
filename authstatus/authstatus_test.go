package authstatus

import (
	"context"
	"testing"

	coresecret "github.com/fluxplane/fluxplane-auth/authsecret"
	sharedsecret "github.com/fluxplane/fluxplane-secret"
)

func TestEvaluateUsesRequiredGroupSetupField(t *testing.T) {
	store := sharedsecret.NewFileStore(t.TempDir())
	if err := store.SaveSecret(context.Background(), sharedsecret.StoredSecret{
		Ref:   coresecret.Plugin("slack", "work", "user_token"),
		Kind:  coresecret.KindBearerToken,
		Value: "slack-user-token",
	}); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	status := Evaluate(context.Background(), store, Target{
		Plugin:   "slack",
		Instance: "work",
		Methods: []coresecret.AuthMethodSpec{{
			Name:   "token",
			Method: coresecret.AuthMethodStored,
			Kind:   coresecret.KindBearerToken,
			SetupFields: []coresecret.SetupFieldSpec{
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
		{Ref: coresecret.Plugin("jira", "work", "email"), Kind: coresecret.KindBasic, Value: "user@example.invalid"},
		{Ref: coresecret.Plugin("jira", "work", "token"), Kind: coresecret.KindBasic, Value: "api-token"},
	} {
		if err := store.SaveSecret(context.Background(), secret); err != nil {
			t.Fatalf("SaveSecret: %v", err)
		}
	}
	status := Evaluate(context.Background(), store, Target{
		Plugin:   "jira",
		Instance: "work",
		Methods: []coresecret.AuthMethodSpec{{
			Name:   "api_token",
			Method: coresecret.AuthMethodStored,
			Kind:   coresecret.KindBasic,
			SetupFields: []coresecret.SetupFieldSpec{
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
	status := Evaluate(context.Background(), coresecret.EnvResolver{Environment: env}, Target{
		Plugin:   "gitlab",
		Instance: "gitlab",
		Methods: []coresecret.AuthMethodSpec{{
			Name:   "personal_access_token",
			Method: coresecret.AuthMethodEnv,
			Kind:   coresecret.KindAPIKey,
			Env:    coresecret.EnvSpec{Aliases: []string{"GITLAB_TOKEN"}},
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
