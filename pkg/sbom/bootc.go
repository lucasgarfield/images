package sbom

import (
	"crypto/sha1" // #nosec G505 -- SPDX 2.3 externalDocumentRefs mandate SHA1
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BootcContainerRefID is the externalDocumentId of the container SBOM in a
// bootc disk SBOM.
const BootcContainerRefID = "DocumentRef-container"

// BootcDisk describes the bootc disk image an SBOM is written for.
type BootcDisk struct {
	Name         string // e.g. fedora-bootc-qcow2-x86_64 (basename)
	Version      string // optional
	ImageType    string // e.g. qcow2
	Arch         string
	File         string // file name of the disk (build only)
	SHA256       string // SHA256 of the disk (build only; empty at manifest time)
	Creators     []string
	Namespace    string
	Tool         string
	Digests      []string // digests the resolved --bootc-ref is known under
	ContainerRef string
}

type spdxDoc = map[string]interface{}

// ContainerSBOMDigests returns the sha256 digests the container SBOM's
// described root package claims (versionInfo, SHA256 checksum, or the
// digest in a pkg:oci purl).
func ContainerSBOMDigests(doc []byte) (rootID string, digests []string, err error) {
	var d spdxDoc
	if err := json.Unmarshal(doc, &d); err != nil {
		return "", nil, fmt.Errorf("cannot parse container SBOM: %w", err)
	}
	if v, _ := d["spdxVersion"].(string); v != "SPDX-2.3" {
		return "", nil, fmt.Errorf("container SBOM: need SPDX-2.3, got %q", v)
	}
	docID, _ := d["SPDXID"].(string)
	rels, _ := d["relationships"].([]interface{})
	var roots []string
	for _, r := range rels {
		m, _ := r.(map[string]interface{})
		if m["spdxElementId"] == docID && m["relationshipType"] == "DESCRIBES" {
			roots = append(roots, m["relatedSpdxElement"].(string))
		}
	}
	if len(roots) != 1 {
		return "", nil, fmt.Errorf("container SBOM must DESCRIBE exactly one root, found %d", len(roots))
	}
	pkgs, _ := d["packages"].([]interface{})
	for _, p := range pkgs {
		m, _ := p.(map[string]interface{})
		if m["SPDXID"] != roots[0] {
			continue
		}
		seen := map[string]bool{}
		add := func(s string) {
			if strings.HasPrefix(s, "sha256:") && len(s) == 71 && !seen[s] {
				seen[s] = true
				digests = append(digests, s)
			}
		}
		if v, ok := m["versionInfo"].(string); ok {
			add(v)
		}
		cs, _ := m["checksums"].([]interface{})
		for _, c := range cs {
			cm, _ := c.(map[string]interface{})
			if cm["algorithm"] == "SHA256" {
				add("sha256:" + cm["checksumValue"].(string))
			}
		}
		refs, _ := m["externalRefs"].([]interface{})
		for _, r := range refs {
			rm, _ := r.(map[string]interface{})
			loc, _ := rm["referenceLocator"].(string)
			if rm["referenceType"] == "purl" && strings.HasPrefix(loc, "pkg:oci/") {
				if i := strings.Index(loc, "@"); i >= 0 {
					v := loc[i+1:]
					if j := strings.IndexAny(v, "?#"); j >= 0 {
						v = v[:j]
					}
					if u, err := url.PathUnescape(v); err == nil {
						add(u)
					}
				}
			}
		}
		return roots[0], digests, nil
	}
	return "", nil, fmt.Errorf("container SBOM: described root %q not found", roots[0])
}

// CheckContainerSBOM refuses a container SBOM whose root does not name one
// of the digests of the resolved bootc container.
func CheckContainerSBOM(doc []byte, digests []string) error {
	_, claimed, err := ContainerSBOMDigests(doc)
	if err != nil {
		return err
	}
	if len(claimed) == 0 {
		return fmt.Errorf("container SBOM root names no sha256 digest")
	}
	for _, c := range claimed {
		for _, d := range digests {
			if c == d {
				return nil
			}
		}
	}
	return fmt.Errorf("container SBOM describes %v, but the bootc container resolves to %v", claimed, digests)
}

// BootcDiskSBOM merges the container SBOM's installed packages inline under
// a new OPERATING_SYSTEM disk root (SPDXRef-image-root) and links the
// container SBOM with externalDocumentRefs + GENERATED_FROM, following the
// proposed disk-image guideline (security-data-guidelines#1): scanners
// ignore cross-document links, so the packages are listed inline.
// Package fields (purls, checksums, licenses, supplier) are kept as-is;
// file-level data is dropped (filesAnalyzed=false) because the container
// SBOM's files are not copied.
func BootcDiskSBOM(container []byte, disk BootcDisk) ([]byte, error) {
	if err := CheckContainerSBOM(container, disk.Digests); err != nil {
		return nil, err
	}
	croot, _, _ := ContainerSBOMDigests(container)
	var c spdxDoc
	if err := json.Unmarshal(container, &c); err != nil {
		return nil, err
	}
	cns, _ := c["documentNamespace"].(string)
	if cns == "" {
		return nil, fmt.Errorf("container SBOM has no documentNamespace")
	}
	cdocID, _ := c["SPDXID"].(string)
	// which packages are installed content: everything except the root
	var pkgs []interface{}
	ids := map[string]bool{}
	cp, _ := c["packages"].([]interface{})
	for _, p := range cp {
		m, _ := p.(map[string]interface{})
		id, _ := m["SPDXID"].(string)
		if id == croot {
			continue
		}
		delete(m, "packageVerificationCode")
		delete(m, "hasFiles")
		m["filesAnalyzed"] = false
		ids[id] = true
		pkgs = append(pkgs, m)
	}
	q := url.Values{}
	q.Set("arch", disk.Arch)
	if disk.ImageType != "" {
		q.Set("image_type", disk.ImageType)
	}
	ver := disk.Version
	if ver == "" {
		ver = "NOASSERTION"
	}
	root := map[string]interface{}{
		"SPDXID": OSRootSPDXID, "name": disk.Name, "versionInfo": ver, "downloadLocation": "NOASSERTION",
		"filesAnalyzed": false, "licenseDeclared": "NOASSERTION", "licenseConcluded": "NOASSERTION", "supplier": "NOASSERTION",
		"primaryPackagePurpose": "OPERATING_SYSTEM",
		"summary":               "bootc disk image built from " + disk.ContainerRef,
		"externalRefs": []interface{}{map[string]interface{}{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
			"referenceLocator": fmt.Sprintf("pkg:generic/%s?%s", url.PathEscape(disk.Name), q.Encode())}},
	}
	if disk.SHA256 != "" {
		root["checksums"] = []interface{}{map[string]interface{}{"algorithm": "SHA256", "checksumValue": disk.SHA256}}
		root["packageFileName"] = disk.File
	}
	rels := []interface{}{
		map[string]interface{}{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": OSRootSPDXID},
		map[string]interface{}{"spdxElementId": OSRootSPDXID, "relationshipType": "GENERATED_FROM", "relatedSpdxElement": BootcContainerRefID + ":" + croot},
	}
	crels, _ := c["relationships"].([]interface{})
	contained := map[string]bool{}
	for _, r := range crels {
		m, _ := r.(map[string]interface{})
		a, _ := m["spdxElementId"].(string)
		b, _ := m["relatedSpdxElement"].(string)
		t, _ := m["relationshipType"].(string)
		switch {
		case (a == croot && t == "CONTAINS") || (a == cdocID && t == "DESCRIBES" && b != croot):
			if ids[b] && !contained[b] {
				contained[b] = true
				rels = append(rels, map[string]interface{}{"spdxElementId": OSRootSPDXID, "relationshipType": "CONTAINS", "relatedSpdxElement": b})
			}
		case ids[a] && ids[b]:
			rels = append(rels, m) // e.g. GENERATED_FROM to SRPMs, DEPENDS_ON
		}
	}
	// packages the container root did not reference explicitly are still installed content
	for id := range ids {
		if !contained[id] {
			rels = append(rels, map[string]interface{}{"spdxElementId": OSRootSPDXID, "relationshipType": "CONTAINS", "relatedSpdxElement": id})
		}
	}
	sum := sha1.Sum(container) // #nosec G401
	ns := disk.Namespace
	if ns == "" {
		ns = "https://example.com/sbom"
	}
	d := spdxDoc{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": disk.Name,
		"documentNamespace": strings.TrimSuffix(ns, "/") + "/" + disk.Name + "-" + uuid.New().String() + ".spdx.json",
		"creationInfo": map[string]interface{}{
			"created": time.Now().UTC().Format(time.RFC3339), "creators": append([]string{disk.Tool}, disk.Creators...),
			"comment": "SBOM generation context: build. Installed packages are merged inline from the container SBOM " + cns + " (--bootc-ref-sbom).",
		},
		"externalDocumentRefs": []interface{}{map[string]interface{}{
			"externalDocumentId": BootcContainerRefID, "spdxDocument": cns,
			"checksum": map[string]interface{}{"algorithm": "SHA1", "checksumValue": hex.EncodeToString(sum[:])},
		}},
		"packages":      append([]interface{}{root}, pkgs...),
		"relationships": rels,
	}
	if li, ok := c["hasExtractedLicensingInfos"]; ok {
		d["hasExtractedLicensingInfos"] = li
	}
	if ci, ok := c["creationInfo"].(map[string]interface{}); ok {
		if v, ok := ci["licenseListVersion"]; ok {
			d["creationInfo"].(map[string]interface{})["licenseListVersion"] = v
		}
	}
	return json.MarshalIndent(d, "", "  ")
}
