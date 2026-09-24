package utils

import (
	"reflect"
	"testing"
)

// duplicateCodeAllowed lists (Code, differing-by-Status) groups that
// intentionally share a client-facing error code across multiple HTTP
// statuses. InvalidPayload/InvalidPayloadSize/InvalidPayloadMedia all use
// "invalid_payload" at 400/413/415 respectively, since from the client's
// perspective they're all "your request body was unusable" — only the
// HTTP status distinguishes why. Uniqueness below is therefore checked on
// the (Code, Status) pair, not Code alone.
var duplicateCodeAllowed = map[string]bool{
	"invalid_payload": true,
}

// TestErrorsRegistry_Sanity walks every field of the Errors registry via
// reflection (so it never needs updating when a new error is added) and
// checks each ErrorDetail is well-formed.
func TestErrorsRegistry_Sanity(t *testing.T) {
	v := reflect.ValueOf(Errors)
	typ := v.Type()

	if v.NumField() == 0 {
		t.Fatal("Errors registry is empty")
	}

	type key struct {
		Code   string
		Status int
	}
	seen := make(map[key]string, v.NumField())

	for i := 0; i < v.NumField(); i++ {
		fieldName := typ.Field(i).Name
		detail, ok := v.Field(i).Interface().(ErrorDetail)
		if !ok {
			t.Fatalf("field %s is not an ErrorDetail", fieldName)
		}

		if detail.Code == "" {
			t.Errorf("%s: Code is empty", fieldName)
		}
		if detail.Message == "" {
			t.Errorf("%s: Message is empty", fieldName)
		}
		if detail.Status < 400 || detail.Status > 599 {
			t.Errorf("%s: Status = %d, want a 4xx/5xx HTTP status", fieldName, detail.Status)
		}

		k := key{Code: detail.Code, Status: detail.Status}
		if existing, dup := seen[k]; dup {
			t.Errorf("%s and %s share identical Code %q and Status %d", fieldName, existing, detail.Code, detail.Status)
		}
		seen[k] = fieldName

		// Even allowing intentional Code reuse across different statuses,
		// flag anything reusing a code that ISN'T on the documented
		// allowlist, so an accidental collision still gets caught.
		if !duplicateCodeAllowed[detail.Code] {
			for otherKey, otherField := range seen {
				if otherKey.Code == detail.Code && otherKey.Status != detail.Status && otherField != fieldName {
					t.Errorf("%s and %s share Code %q at different statuses (%d vs %d) but %q isn't on the documented allowlist",
						fieldName, otherField, detail.Code, detail.Status, otherKey.Status, detail.Code)
				}
			}
		}
	}
}
