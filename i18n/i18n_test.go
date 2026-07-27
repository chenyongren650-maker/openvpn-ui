package i18n

import (
	"html/template"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var (
	referencedGoKeyPattern       = regexp.MustCompile(`\.T\(\s*"((?:alert|api|breadcrumb|certificate|client|client_config|common|config|connection|dashboard|easyrsa|error|login|logout|logs|maintenance|nav|navigation|notifications|oauth|profile|server|settings|theme|totp|validation)(?:\.[a-z0-9_]+)+)"`)
	referencedTemplateKeyPattern = regexp.MustCompile(`\{\{\s*t\s+(?:\.|\$\.)Localizer\s+"((?:alert|api|breadcrumb|certificate|client|client_config|common|config|connection|dashboard|easyrsa|error|login|logout|logs|maintenance|nav|navigation|notifications|oauth|profile|server|settings|theme|totp|validation)(?:\.[a-z0-9_]+)+)"`)
)

func TestLoadCatalogAndTranslate(t *testing.T) {
	catalog, err := LoadCatalog(filepath.Join("..", "locales"))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}

	if got := catalog.Localizer(DefaultLanguage).T("nav.home"); got != "首页" {
		t.Fatalf("Chinese nav.home = %q", got)
	}
	if got := catalog.Localizer(EnglishLanguage).T("nav.home"); got != "Home" {
		t.Fatalf("English nav.home = %q", got)
	}
	if got := catalog.Localizer("unsupported").Language(); got != DefaultLanguage {
		t.Fatalf("unsupported language resolved to %q", got)
	}
	if got := catalog.Localizer(DefaultLanguage).T("missing.key"); got != "missing.key" {
		t.Fatalf("missing key fallback = %q", got)
	}
	if got := catalog.Localizer(DefaultLanguage).T("certificate.created", "alice"); got != "证书“alice”创建成功" {
		t.Fatalf("formatted translation = %q", got)
	}
}

func TestResolveLanguage(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		cookie string
		want   string
	}{
		{name: "default Chinese", want: DefaultLanguage},
		{name: "cookie English", cookie: EnglishLanguage, want: EnglishLanguage},
		{name: "query overrides cookie", query: DefaultLanguage, cookie: EnglishLanguage, want: DefaultLanguage},
		{name: "invalid query uses cookie", query: "fr-FR", cookie: EnglishLanguage, want: EnglishLanguage},
		{name: "language identifier is exact", query: "en-us", cookie: DefaultLanguage, want: DefaultLanguage},
		{name: "invalid values default Chinese", query: "fr-FR", cookie: "de-DE", want: DefaultLanguage},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ResolveLanguage(test.query, test.cookie); got != test.want {
				t.Fatalf("ResolveLanguage(%q, %q) = %q, want %q", test.query, test.cookie, got, test.want)
			}
		})
	}
}

func TestLanguageURL(t *testing.T) {
	current, err := url.Parse("/certificates?page=2&lang=zh-CN")
	if err != nil {
		t.Fatal(err)
	}
	if got := LanguageURL(current, EnglishLanguage); got != "/certificates?lang=en-US&page=2" {
		t.Fatalf("LanguageURL() = %q", got)
	}
	if got := LanguageURL(current, "invalid"); got != "/certificates?lang=zh-CN&page=2" {
		t.Fatalf("LanguageURL() invalid fallback = %q", got)
	}
}

func TestLoadCatalogRejectsMismatchedKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DefaultLanguage+".json"), []byte(`{"only.zh":"值"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnglishLanguage+".json"), []byte(`{"only.en":"value"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCatalog(dir)
	if err == nil || !strings.Contains(err.Error(), "missing key") {
		t.Fatalf("LoadCatalog() error = %v, want missing key", err)
	}
}

func TestLoadCatalogRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DefaultLanguage+".json"), []byte(`{"key":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnglishLanguage+".json"), []byte(`{"key":"value"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCatalog(dir)
	if err == nil || !strings.Contains(err.Error(), "parse language file") {
		t.Fatalf("LoadCatalog() error = %v, want JSON parse error", err)
	}
}

func TestLoadCatalogRejectsEmptyTranslation(t *testing.T) {
	dir := t.TempDir()
	for _, language := range SupportedLanguages() {
		if err := os.WriteFile(filepath.Join(dir, language+".json"), []byte(`{"key":""}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	_, err := LoadCatalog(dir)
	if err == nil || !strings.Contains(err.Error(), "empty key or value") {
		t.Fatalf("LoadCatalog() error = %v, want empty value error", err)
	}
}

func TestLoadCatalogRejectsMismatchedPlaceholders(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DefaultLanguage+".json"), []byte(`{"message":"用户 %s"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnglishLanguage+".json"), []byte(`{"message":"User %d"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCatalog(dir)
	if err == nil || !strings.Contains(err.Error(), "mismatched format placeholders") {
		t.Fatalf("LoadCatalog() error = %v, want placeholder mismatch", err)
	}
}

func TestLocalizersAreRequestScoped(t *testing.T) {
	catalog, err := LoadCatalog(filepath.Join("..", "locales"))
	if err != nil {
		t.Fatal(err)
	}

	zh := catalog.Localizer(DefaultLanguage)
	en := catalog.Localizer(EnglishLanguage)

	var wait sync.WaitGroup
	errors := make(chan string, 2)
	check := func(localizer *Localizer, want string) {
		defer wait.Done()
		for index := 0; index < 1000; index++ {
			if got := localizer.T("nav.home"); got != want {
				errors <- got
				return
			}
		}
	}
	wait.Add(2)
	go check(zh, "首页")
	go check(en, "Home")
	wait.Wait()
	close(errors)
	for got := range errors {
		t.Fatalf("request-scoped translation changed to %q", got)
	}
}

func TestReferencedTranslationKeysExist(t *testing.T) {
	catalog, err := LoadCatalog(filepath.Join("..", "locales"))
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{"../controllers", "../lib", "../views"} {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || (filepath.Ext(path) != ".go" && filepath.Ext(path) != ".html") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			pattern := referencedGoKeyPattern
			if filepath.Ext(path) == ".html" {
				pattern = referencedTemplateKeyPattern
			}
			for _, match := range pattern.FindAllSubmatch(data, -1) {
				key := string(match[1])
				if _, exists := catalog.messages[DefaultLanguage][key]; !exists {
					t.Errorf("%s references missing translation key %q", path, key)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestTemplatesParse(t *testing.T) {
	funcs := template.FuncMap{
		"compare":             func(...interface{}) bool { return false },
		"dateformat":          func(...interface{}) string { return "" },
		"field_error_exist":   func(...interface{}) bool { return false },
		"field_error_message": func(...interface{}) interface{} { return nil },
		"formatunixtime":      func(...interface{}) string { return "" },
		"percent":             func(...interface{}) string { return "" },
		"printkb":             func(...interface{}) string { return "" },
		"printmb":             func(...interface{}) string { return "" },
		"t":                   func(...interface{}) string { return "" },
		"urlfor":              func(...interface{}) string { return "" },
	}

	err := filepath.WalkDir("../views", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".html" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if _, parseErr := template.New(filepath.Base(path)).Funcs(funcs).Parse(string(data)); parseErr != nil {
			t.Errorf("parse template %s: %v", path, parseErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTemplatesDoNotContainLegacyNetworkExamples(t *testing.T) {
	legacyExamples := []string{"10.0.70.0/24", "10.0.71.0/24", "10.0.70.0 255.255.255.0", "10.0.71.0 255.255.255.0"}
	err := filepath.WalkDir("../views", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".html" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, example := range legacyExamples {
			if strings.Contains(string(data), example) {
				t.Errorf("%s contains legacy network example %q", path, example)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
