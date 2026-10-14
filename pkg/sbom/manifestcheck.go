package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ManifestRPMChecksums returns the "sha256:<hex>" ids of all RPM sources
// (org.osbuild.librepo / org.osbuild.curl) of an osbuild manifest.
func ManifestRPMChecksums(manifest []byte) (map[string]bool, error) {
	var m struct {
		Sources map[string]struct {
			Items map[string]json.RawMessage `json:"items"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("cannot parse manifest: %w", err)
	}
	sums := map[string]bool{}
	for name, src := range m.Sources {
		if name != "org.osbuild.librepo" && name != "org.osbuild.curl" {
			continue
		}
		for id := range src.Items {
			sums[id] = true
		}
	}
	return sums, nil
}

// CheckSPDXAgainstManifest verifies that every RPM package (SHA256
// checksum) listed in an SPDX document is a source of the manifest.
func CheckSPDXAgainstManifest(doc []byte, sums map[string]bool) error {
	var d struct {
		Packages []struct {
			Name            string `json:"name"`
			PackageFileName string `json:"packageFileName"`
			Checksums       []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"checksumValue"`
			} `json:"checksums"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return fmt.Errorf("cannot parse SPDX: %w", err)
	}
	n := 0
	for _, p := range d.Packages {
		if !strings.HasSuffix(p.PackageFileName, ".rpm") || strings.HasSuffix(p.PackageFileName, ".src.rpm") {
			continue
		}
		for _, c := range p.Checksums {
			if c.Algorithm != "SHA256" {
				continue
			}
			if !sums["sha256:"+c.Value] {
				return fmt.Errorf("package %s (sha256:%s) is not in the manifest", p.Name, c.Value)
			}
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("no RPM checksums to check")
	}
	return nil
}
