package sbom

import (
	"encoding/json"
	"fmt"
)

// OSRoot describes the image an SBOM is about. It is used to add a single
// root package (primaryPackagePurpose OPERATING_SYSTEM) to an SPDX document
// that otherwise only DESCRIBES a flat list of RPM packages. Consumers such
// as Konflux mobster, mequal and TPA expect exactly one described root.
type OSRoot struct {
	// Name of the image, e.g. "fedora-44-qcow2-x86_64"
	Name string
	// Version of the image/distribution, e.g. "44"
	Version string
	// Optional package URL for the image
	PURL string
	// Optional CPE (2.2 URI form, e.g. cpe:/o:redhat:enterprise_linux:9)
	CPE string
	// Optional SPDX checksums (algorithm -> hex) of the final artifact
	Checksums map[string]string
	// Summary is an optional human readable description of the root.
	Summary string
}

const OSRootSPDXID = "SPDXRef-image-root"

// AddSPDXOSRoot returns a copy of the SPDX 2.3 JSON document with an OS root
// package. Every package that was DESCRIBED by the document becomes
// CONTAINED by the root, and the document only DESCRIBES the root.
func AddSPDXOSRoot(doc json.RawMessage, root OSRoot) (json.RawMessage, error) {
	var d map[string]interface{}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("cannot parse SPDX document: %w", err)
	}
	docID, _ := d["SPDXID"].(string)
	if docID == "" {
		docID = "SPDXRef-DOCUMENT"
	}

	refs := []interface{}{}
	if root.PURL != "" {
		refs = append(refs, map[string]interface{}{
			"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": root.PURL,
		})
	}
	if root.CPE != "" {
		refs = append(refs, map[string]interface{}{
			"referenceCategory": "SECURITY", "referenceType": "cpe22Type", "referenceLocator": root.CPE,
		})
	}
	pkg := map[string]interface{}{
		"SPDXID":                OSRootSPDXID,
		"name":                  root.Name,
		"versionInfo":           root.Version,
		"downloadLocation":      "NOASSERTION",
		"filesAnalyzed":         false,
		"licenseDeclared":       "NOASSERTION",
		"licenseConcluded":      "NOASSERTION",
		"primaryPackagePurpose": "OPERATING_SYSTEM",
		"supplier":              "NOASSERTION",
	}
	if root.Summary != "" {
		pkg["summary"] = root.Summary
	}
	if len(refs) > 0 {
		pkg["externalRefs"] = refs
	}
	if len(root.Checksums) > 0 {
		cs := []interface{}{}
		for alg, val := range root.Checksums {
			cs = append(cs, map[string]interface{}{"algorithm": alg, "checksumValue": val})
		}
		pkg["checksums"] = cs
	}

	pkgs, _ := d["packages"].([]interface{})
	d["packages"] = append([]interface{}{pkg}, pkgs...)

	rels, _ := d["relationships"].([]interface{})
	newRels := []interface{}{map[string]interface{}{
		"spdxElementId": docID, "relationshipType": "DESCRIBES", "relatedSpdxElement": OSRootSPDXID,
	}}
	for _, r := range rels {
		rel, ok := r.(map[string]interface{})
		if ok && rel["relationshipType"] == "DESCRIBES" && rel["spdxElementId"] == docID {
			rel["spdxElementId"] = OSRootSPDXID
			rel["relationshipType"] = "CONTAINS"
		}
		newRels = append(newRels, r)
	}
	d["relationships"] = newRels
	if root.Name != "" {
		d["name"] = root.Name
	}
	return json.Marshal(d)
}
