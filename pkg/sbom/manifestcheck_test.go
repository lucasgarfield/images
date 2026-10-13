package sbom

import "testing"

func TestCheckSPDXAgainstManifest(t *testing.T) {
	mf := []byte(`{"sources":{"org.osbuild.librepo":{"items":{"sha256:aa":{}}}}}`)
	sums, err := ManifestRPMChecksums(mf)
	if err != nil {
		t.Fatal(err)
	}
	ok := []byte(`{"packages":[{"name":"a","packageFileName":"a.rpm","checksums":[{"algorithm":"SHA256","checksumValue":"aa"}]},{"name":"a-src","packageFileName":"a.src.rpm"}]}`)
	if err := CheckSPDXAgainstManifest(ok, sums); err != nil {
		t.Fatal(err)
	}
	bad := []byte(`{"packages":[{"name":"b","packageFileName":"b.rpm","checksums":[{"algorithm":"SHA256","checksumValue":"bb"}]}]}`)
	if err := CheckSPDXAgainstManifest(bad, sums); err == nil {
		t.Fatal("expected mismatch")
	}
}
