// Package apidocs provides the same OpenAPI document shipped in the repository.
package apidocs

import _ "embed"

//go:embed openapi.yaml
var OpenAPI []byte

//go:embed agent-openapi.yaml
var AgentOpenAPI []byte
