package sbom

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const flatDoc = `{"SPDXID":"SPDXRef-DOCUMENT","name":"sbom-by-osbuild","spdxVersion":"SPDX-2.3",
"packages":[{"SPDXID":"SPDXRef-a","name":"a"},{"SPDXID":"SPDXRef-b","name":"b"}],
"relationships":[
 {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-a"},
 {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-b"},
 {"spdxElementId":"SPDXRef-b","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-a"}]}`

func TestAddSPDXOSRoot(t *testing.T) {
	out, err := AddSPDXOSRoot(json.RawMessage(flatDoc), OSRoot{Name: "fedora-44-qcow2-x86_64", Version: "44", PURL: "pkg:generic/fedora-44-qcow2-x86_64@44"})
	require.NoError(t, err)
	var d map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &d))
	assert.Equal(t, "fedora-44-qcow2-x86_64", d["name"])
	root := d["packages"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "OPERATING_SYSTEM", root["primaryPackagePurpose"])
	counts := map[string]int{}
	for _, r := range d["relationships"].([]interface{}) {
		rel := r.(map[string]interface{})
		counts[rel["relationshipType"].(string)]++
		if rel["relationshipType"] == "DESCRIBES" {
			assert.Equal(t, OSRootSPDXID, rel["relatedSpdxElement"])
		}
		if rel["relationshipType"] == "CONTAINS" {
			assert.Equal(t, OSRootSPDXID, rel["spdxElementId"])
		}
	}
	assert.Equal(t, map[string]int{"DESCRIBES": 1, "CONTAINS": 2, "DEPENDS_ON": 1}, counts)
}

func TestAddSPDXOSRootFields(t *testing.T) {
	out, err := AddSPDXOSRoot(json.RawMessage(`{"SPDXID":"SPDXRef-DOCUMENT"}`), OSRoot{Name: "br", Version: "9", Summary: "build root"})
	require.NoError(t, err)
	var d map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &d))
	root := d["packages"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "build root", root["summary"])
	assert.Equal(t, "NOASSERTION", root["licenseConcluded"])
	assert.Equal(t, "NOASSERTION", root["licenseDeclared"])
	assert.Equal(t, "br", d["name"])
}
