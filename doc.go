// Package auth defines declarative authentication contracts for providers and
// plugins.
//
// Auth does not acquire credentials, store secrets, refresh tokens, prompt
// users, approve access, or call provider APIs. Runtime packages use these
// inert declarations to decide which authentication setup a provider supports
// and which credential material is required.
package auth
