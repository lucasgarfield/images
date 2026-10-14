package sbom

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkSPDXBuildroot(t *testing.T) {
	img := json.RawMessage(`{"SPDXID":"SPDXRef-DOCUMENT","relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-image-root"}]}`)
	br := []byte(`{"SPDXID":"SPDXRef-DOCUMENT","documentNamespace":"https://example.com/br"}` + "\n")
	out, err := LinkSPDXBuildroot(img, br, "build")
	require.NoError(t, err)
	var d map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &d))
	refs := d["externalDocumentRefs"].([]interface{})
	require.Len(t, refs, 1)
	ref := refs[0].(map[string]interface{})
	assert.Equal(t, "DocumentRef-buildroot-build", ref["externalDocumentId"])
	assert.Equal(t, "https://example.com/br", ref["spdxDocument"])
	assert.Len(t, ref["checksum"].(map[string]interface{})["checksumValue"], 40)
	rels := d["relationships"].([]interface{})
	require.Len(t, rels, 2)
	assert.Equal(t, map[string]interface{}{
		"spdxElementId": "DocumentRef-buildroot-build:SPDXRef-DOCUMENT", "relationshipType": "BUILD_TOOL_OF", "relatedSpdxElement": "SPDXRef-image-root",
	}, rels[1])

	_, err = LinkSPDXBuildroot(img, []byte(`{}`), "build")
	assert.Error(t, err)
}

func TestAnnotateSPDXCreationInfo(t *testing.T) {
	doc := json.RawMessage(`{"creationInfo":{"creators":["Tool: osbuild-1"],"created":"x"}}`)
	out, err := AnnotateSPDXCreationInfo(doc, []string{"Organization: Red Hat", "Tool: osbuild-1"}, "ctx")
	require.NoError(t, err)
	var d map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &d))
	ci := d["creationInfo"].(map[string]interface{})
	assert.Equal(t, []interface{}{"Tool: osbuild-1", "Organization: Red Hat"}, ci["creators"])
	assert.Equal(t, "ctx", ci["comment"])
	assert.Equal(t, "x", ci["created"])
}
