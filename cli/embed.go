//go:build embedpubkey

package cli

import _ "embed"

//go:embed pub.pem
var EmbeddedPublicKeyPEM string
