package sbom

import (
	"crypto/sha1" // #nosec G505 -- SPDX 2.3 externalDocumentRefs mandate SHA1
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// BuildrootRefPrefix is the externalDocumentId prefix used for linked
// build-root SBOM documents.
const BuildrootRefPrefix = "DocumentRef-buildroot-"

// LinkSPDXBuildroot returns a copy of the image SPDX document that references
// the (already serialized) build-root SPDX document via externalDocumentRefs
// and records "<buildroot document> BUILD_TOOL_OF <described root>".
// The build root stays in its own document, so scanners and Trustify do not
// attribute its packages to the image, while coverage/provenance is kept
// (CISA 2026 "Coverage": linked SBOMs; Red Hat guide: build-only dependencies
// listed separately from runtime ones).
func LinkSPDXBuildroot(doc json.RawMessage, buildroot []byte, name string) (json.RawMessage, error) {
	var d map[string]interface{}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("cannot parse SPDX document: %w", err)
	}
	var br map[string]interface{}
	if err := json.Unmarshal(buildroot, &br); err != nil {
		return nil, fmt.Errorf("cannot parse build-root SPDX document: %w", err)
	}
	ns, _ := br["documentNamespace"].(string)
	if ns == "" {
		return nil, fmt.Errorf("build-root SPDX document has no documentNamespace")
	}
	sum := sha1.Sum(buildroot) // #nosec G401
	refID := BuildrootRefPrefix + name
	refs, _ := d["externalDocumentRefs"].([]interface{})
	d["externalDocumentRefs"] = append(refs, map[string]interface{}{
		"externalDocumentId": refID,
		"spdxDocument":       ns,
		"checksum":           map[string]interface{}{"algorithm": "SHA1", "checksumValue": hex.EncodeToString(sum[:])},
	})
	docID, _ := d["SPDXID"].(string)
	rels, _ := d["relationships"].([]interface{})
	roots := []string{}
	for _, r := range rels {
		rel, ok := r.(map[string]interface{})
		if ok && rel["relationshipType"] == "DESCRIBES" && rel["spdxElementId"] == docID {
			if id, ok := rel["relatedSpdxElement"].(string); ok {
				roots = append(roots, id)
			}
		}
	}
	for _, root := range roots {
		rels = append(rels, map[string]interface{}{
			"spdxElementId":      refID + ":SPDXRef-DOCUMENT",
			"relationshipType":   "BUILD_TOOL_OF",
			"relatedSpdxElement": root,
		})
	}
	d["relationships"] = rels
	return json.Marshal(d)
}

// AnnotateSPDXCreationInfo returns a copy of the SPDX document with extra
// creators (e.g. "Organization: Red Hat", the SBOM author) appended and the
// creationInfo comment set (used for the CISA 2026 "SBOM Generation Context").
func AnnotateSPDXCreationInfo(doc json.RawMessage, creators []string, comment string) (json.RawMessage, error) {
	var d map[string]interface{}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("cannot parse SPDX document: %w", err)
	}
	ci, _ := d["creationInfo"].(map[string]interface{})
	if ci == nil {
		ci = map[string]interface{}{}
	}
	existing, _ := ci["creators"].([]interface{})
	seen := map[string]bool{}
	for _, c := range existing {
		if s, ok := c.(string); ok {
			seen[s] = true
		}
	}
	for _, c := range creators {
		if !seen[c] {
			existing = append(existing, c)
			seen[c] = true
		}
	}
	ci["creators"] = existing
	if comment != "" {
		ci["comment"] = comment
	}
	d["creationInfo"] = ci
	return json.Marshal(d)
}
