//go:build embedransom

package ransom

import _ "embed"

//go:embed IMPORTANT.txt
var EmbeddedTemplate string
