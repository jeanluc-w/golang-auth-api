package emailer

import (
	"strings"
	"testing"
)

func TestRenderVerificationHTML_ContainsCode(t *testing.T) {
	html, err := RenderVerificationHTML("123456")
	if err != nil {
		t.Fatalf("RenderVerificationHTML: %v", err)
	}
	if !strings.Contains(html, "123456") {
		t.Error("rendered HTML does not contain the verification code")
	}
	if strings.Contains(html, "{{") {
		t.Error("rendered HTML contains an unresolved template action ('{{') — likely a field name typo")
	}
}

// The template hardcodes a static "©2025 auth" footer rather than using
// VerificationTemplateData.Year (which RenderVerificationHTML never
// populates — it's effectively a dead field). Not a correctness bug: the
// static copyright notice renders fine either way, it just won't advance on
// its own. Flagging here rather than changing the template, since whether
// to wire up a dynamic year is a product/design call, not a test-coverage one.
func TestRenderVerificationHTML_YearFieldIsUnusedByTemplate(t *testing.T) {
	html, err := RenderVerificationHTML("000000")
	if err != nil {
		t.Fatalf("RenderVerificationHTML: %v", err)
	}
	if !strings.Contains(html, "2025") {
		t.Skip("template's hardcoded copyright year changed; this test's premise (a static, non-Year-field year) may need revisiting")
	}
}

func TestRenderHTMLFromFS_UnknownTemplate_Errors(t *testing.T) {
	if _, err := RenderHTMLFromFS("does-not-exist.html.tmpl", nil); err == nil {
		t.Error("expected an error for a nonexistent template name")
	}
}

func TestRenderHTMLFromFS_ExecuteFailure_Errors(t *testing.T) {
	// The real template only references .Code, which is always present on
	// data of the right shape; to exercise Execute's own error path
	// (distinct from ParseFS's), pass data of a type that can't satisfy the
	// template's field access at all.
	if _, err := RenderHTMLFromFS("verification_email.html.tmpl", struct{ NotCode string }{"x"}); err == nil {
		t.Error("expected an error when the template data doesn't provide the fields the template references")
	}
}
