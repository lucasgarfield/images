package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordSPDXArtifactOnRoot(t *testing.T) {
	doc := json.RawMessage(`{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"comment":"SBOM generation context: build."},"packages":[{"SPDXID":"SPDXRef-image-root","name":"x"}]}`)
	out, err := RecordSPDXArtifact(doc, "/out/disk.qcow2", "ab12")
	require.NoError(t, err)
	var d map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &d))
	root := d["packages"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "disk.qcow2", root["packageFileName"])
	assert.Equal(t, []interface{}{map[string]interface{}{"algorithm": "SHA256", "checksumValue": "ab12"}}, root["checksums"])
	assert.Equal(t, "SBOM generation context: build. "+ArtifactGenerationComment, d["creationInfo"].(map[string]interface{})["comment"])

	// idempotent
	out2, err := RecordSPDXArtifact(out, "/out/disk.qcow2", "ab12")
	require.NoError(t, err)
	assert.JSONEq(t, string(out), string(out2))
}

func TestRecordSPDXArtifactWithoutRoot(t *testing.T) {
	doc := json.RawMessage(`{"SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"SPDXRef-a"}],"relationships":[]}`)
	out, err := RecordSPDXArtifact(doc, "img.tar", "ff")
	require.NoError(t, err)
	var d map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &d))
	pkgs := d["packages"].([]interface{})
	require.Len(t, pkgs, 2)
	assert.Equal(t, "FILE", pkgs[1].(map[string]interface{})["primaryPackagePurpose"])
	assert.Equal(t, "SPDXRef-image-artifact", d["relationships"].([]interface{})[0].(map[string]interface{})["relatedSpdxElement"])
}

func TestRecordSPDXArtifactFile(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.raw")
	require.NoError(t, os.WriteFile(img, []byte("hello\n"), 0600))
	sb := filepath.Join(dir, "x.spdx.json")
	require.NoError(t, os.WriteFile(sb, []byte(`{"packages":[{"SPDXID":"SPDXRef-image-root"}]}`), 0600))
	sum, err := RecordSPDXArtifactFile(sb, img)
	require.NoError(t, err)
	// sha256sum of "hello\n"
	assert.Equal(t, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03", sum)
	b, err := os.ReadFile(sb)
	require.NoError(t, err)
	assert.Contains(t, string(b), sum)
}
