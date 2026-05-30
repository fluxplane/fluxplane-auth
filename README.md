# fluxplane-auth

Shared authentication contract types for Fluxplane modules.

This module intentionally contains portable data structures only. It defines auth method declarations, setup fields, OAuth2 metadata, and normalized auth requests that can be exchanged between Fluxplane runtimes, plugins, and distribution layers without depending on `fluxplane-core`.

## Usage

```go
import auth "github.com/fluxplane/fluxplane-auth"

req := auth.Request{
    Plugin:   "slack",
    Instance: "workspace-prod",
    Purpose:  "bot_token",
}
ref := req.SecretRef()
```

## Packages

- `auth.MethodSpec` describes supported authentication methods.
- `auth.FieldSpec` describes connect/setup fields.
- `auth.Request` normalizes plugin/instance/purpose auth lookups.

This package is versioned independently so downstream modules can share auth contracts without importing Fluxplane runtime implementations.
