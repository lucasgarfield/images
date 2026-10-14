package sbom

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetSPDXNamespace(t *testing.T) {
	doc := json.RawMessage(`{"documentNamespace":"https://osbuild.org/spdxdocs/sbom-by-osbuild-194-1234"}`)
	out, err := SetSPDXNamespace(doc, "https://www.redhat.com/")
	require.NoError(t, err)
	assert.JSONEq(t, `{"documentNamespace":"https://www.redhat.com/sbom-by-osbuild-194-1234.spdx.json"}`, string(out))
	same, err := SetSPDXNamespace(doc, "")
	require.NoError(t, err)
	assert.Equal(t, doc, same)
}
