package sbom

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// SetSPDXNamespace replaces the documentNamespace of an SPDX document with
// "<base>/<DocumentID>.spdx.json" (Red Hat SBOM guide, "Document Structure":
// https://www.redhat.com/[DocumentID].spdx.json). DocumentID is the last path
// segment of the current namespace, which is unique per document.
func SetSPDXNamespace(doc json.RawMessage, base string) (json.RawMessage, error) {
	if base == "" {
		return doc, nil
	}
	var d map[string]interface{}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("cannot parse SPDX document: %w", err)
	}
	ns, _ := d["documentNamespace"].(string)
	id := strings.TrimSuffix(ns[strings.LastIndex(ns, "/")+1:], ".spdx.json")
	if id == "" {
		name, _ := d["name"].(string)
		id = strings.TrimPrefix(name+"-", "-") + uuid.NewString()
	}
	d["documentNamespace"] = strings.TrimRight(base, "/") + "/" + id + ".spdx.json"
	return json.Marshal(d)
}
