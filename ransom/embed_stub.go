//go:build !embedransom

package ransom

// EmbeddedTemplate is empty unless the binary is built with -tags embedransom.
var EmbeddedTemplate string
