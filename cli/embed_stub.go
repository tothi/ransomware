//go:build !embedpubkey

package cli

// EmbeddedPublicKeyPEM is empty unless the binary is built with -tags embedpubkey.
var EmbeddedPublicKeyPEM string
