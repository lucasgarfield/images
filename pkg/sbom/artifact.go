package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ArtifactGenerationComment is appended to creationInfo.comment when the
// checksum of the built artifact is recorded (CISA 2026 "SBOM Generation
// Context": the document is completed after the build).
const ArtifactGenerationComment = "Updated after build with the SHA256 checksum and file name of the produced image artifact."

// FileSHA256 returns the hex encoded SHA256 of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RecordSPDXArtifact records the finished image artifact (file name and
// SHA256) in an image SPDX document. With an OS root package
// (SPDXRef-image-root) the checksum and packageFileName are set on the root;
// otherwise a FILE package for the artifact is added and DESCRIBED by the
// document. Must only be called after the artifact was produced, so
// manifest-only SBOMs never carry a checksum.
func RecordSPDXArtifact(doc json.RawMessage, artifactPath, sha256Hex string) (json.RawMessage, error) {
	var d map[string]interface{}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("cannot parse SPDX document: %w", err)
	}
	fileName := filepath.Base(artifactPath)
	checksum := map[string]interface{}{"algorithm": "SHA256", "checksumValue": sha256Hex}
	pkgs, _ := d["packages"].([]interface{})
	var root map[string]interface{}
	for _, p := range pkgs {
		if pm, ok := p.(map[string]interface{}); ok && pm["SPDXID"] == OSRootSPDXID {
			root = pm
		}
	}
	if root == nil {
		root = map[string]interface{}{
			"SPDXID":                "SPDXRef-image-artifact",
			"name":                  fileName,
			"downloadLocation":      "NOASSERTION",
			"filesAnalyzed":         false,
			"licenseConcluded":      "NOASSERTION",
			"primaryPackagePurpose": "FILE",
			"supplier":              "NOASSERTION",
		}
		d["packages"] = append(pkgs, root)
		docID, _ := d["SPDXID"].(string)
		if docID == "" {
			docID = "SPDXRef-DOCUMENT"
		}
		rels, _ := d["relationships"].([]interface{})
		d["relationships"] = append(rels, map[string]interface{}{
			"spdxElementId": docID, "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-image-artifact",
		})
	}
	sums := []interface{}{checksum}
	if old, ok := root["checksums"].([]interface{}); ok {
		for _, c := range old {
			if cm, ok := c.(map[string]interface{}); ok && cm["algorithm"] != "SHA256" {
				sums = append(sums, c)
			}
		}
	}
	root["checksums"] = sums
	root["packageFileName"] = fileName

	ci, _ := d["creationInfo"].(map[string]interface{})
	if ci == nil {
		ci = map[string]interface{}{}
		d["creationInfo"] = ci
	}
	comment, _ := ci["comment"].(string)
	if !strings.Contains(comment, ArtifactGenerationComment) {
		ci["comment"] = strings.TrimSpace(comment + " " + ArtifactGenerationComment)
	}
	return json.Marshal(d)
}

// RecordSPDXArtifactFile updates the SPDX file at sbomPath in place, see
// RecordSPDXArtifact. It returns the recorded SHA256.
func RecordSPDXArtifactFile(sbomPath, artifactPath string) (string, error) {
	sum, err := FileSHA256(artifactPath)
	if err != nil {
		return "", err
	}
	doc, err := os.ReadFile(sbomPath)
	if err != nil {
		return "", err
	}
	out, err := RecordSPDXArtifact(doc, artifactPath, sum)
	if err != nil {
		return "", err
	}
	// #nosec G306
	return sum, os.WriteFile(sbomPath, append(out, '\n'), 0644)
}
