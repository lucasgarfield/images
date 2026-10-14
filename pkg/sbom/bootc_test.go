package sbom_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder/pkg/sbom"
)

const dig = "sha256:36c8aac4265d19d14d1d552b0b70a25ede3a3c04689d703e1cc8aa3c46176f6a"

var ctr = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","documentNamespace":"https://example.com/c",
"packages":[{"SPDXID":"SPDXRef-root","name":"quay.io/fedora/fedora-bootc","versionInfo":"` + dig + `","primaryPackagePurpose":"CONTAINER"},
{"SPDXID":"SPDXRef-bash","name":"bash","versionInfo":"5.3.9-3.fc44","filesAnalyzed":true,"packageVerificationCode":{"packageVerificationCodeValue":"x"},
 "licenseDeclared":"GPL-3.0-or-later","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:rpm/fedora/bash@5.3.9-3.fc44?arch=x86_64"}]}],
"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-root"},
{"spdxElementId":"SPDXRef-root","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-bash"}]}`

func TestBootcDiskSBOMMerges(t *testing.T) {
	out, err := sbom.BootcDiskSBOM([]byte(ctr), sbom.BootcDisk{Name: "disk", Arch: "x86_64", ImageType: "qcow2", File: "disk.qcow2", SHA256: "ab", Tool: "Tool: t", Digests: []string{"sha256:list", dig}})
	require.NoError(t, err)
	var d map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &d))
	pk := d["packages"].([]interface{})
	require.Len(t, pk, 2)
	root := pk[0].(map[string]interface{})
	assert.Equal(t, "SPDXRef-image-root", root["SPDXID"])
	assert.Equal(t, "OPERATING_SYSTEM", root["primaryPackagePurpose"])
	assert.Equal(t, "ab", root["checksums"].([]interface{})[0].(map[string]interface{})["checksumValue"])
	bash := pk[1].(map[string]interface{})
	assert.Equal(t, "GPL-3.0-or-later", bash["licenseDeclared"])
	assert.Equal(t, false, bash["filesAnalyzed"])
	assert.NotContains(t, bash, "packageVerificationCode")
	s := string(out)
	assert.Contains(t, s, `"relatedSpdxElement": "DocumentRef-container:SPDXRef-root"`)
	assert.Contains(t, s, `"relatedSpdxElement": "SPDXRef-bash"`)
	assert.Contains(t, s, `"externalDocumentId": "DocumentRef-container"`)
}

func TestBootcDiskSBOMRefusesDigestMismatch(t *testing.T) {
	_, err := sbom.BootcDiskSBOM([]byte(ctr), sbom.BootcDisk{Name: "disk", Digests: []string{"sha256:0000000000000000000000000000000000000000000000000000000000000000"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "container SBOM describes")
}

func TestBootcDiskSBOMManifestTimeHasNoChecksum(t *testing.T) {
	out, err := sbom.BootcDiskSBOM([]byte(ctr), sbom.BootcDisk{Name: "disk", Digests: []string{dig}})
	require.NoError(t, err)
	assert.NotContains(t, string(out), `"checksums"`)
}
