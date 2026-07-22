package i18n

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
)

const (
	DefaultLanguage = "zh-CN"
	EnglishLanguage = "en-US"
	CookieName      = "openvpn_ui_lang"
)

var languages = []string{DefaultLanguage, EnglishLanguage}

// Catalog contains immutable translations loaded during application startup.
type Catalog struct {
	messages map[string]map[string]string
}

// Localizer is request scoped so concurrent users can select different languages.
type Localizer struct {
	catalog  *Catalog
	language string
}

var activeCatalog atomic.Pointer[Catalog]

// Load reads and validates all supported language files, then activates the catalog.
func Load(dir string) error {
	catalog, err := LoadCatalog(dir)
	if err != nil {
		return err
	}
	activeCatalog.Store(catalog)
	return nil
}

// LoadCatalog reads all language files and rejects missing, extra, or empty entries.
func LoadCatalog(dir string) (*Catalog, error) {
	messages := make(map[string]map[string]string, len(languages))
	for _, language := range languages {
		path := filepath.Join(dir, language+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read language file %s: %w", path, err)
		}

		entries := make(map[string]string)
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("parse language file %s: %w", path, err)
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf("language file %s is empty", path)
		}
		for key, value := range entries {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
				return nil, fmt.Errorf("language file %s contains an empty key or value", path)
			}
		}
		messages[language] = entries
	}

	baseline := messages[DefaultLanguage]
	for _, language := range languages {
		entries := messages[language]
		for key := range baseline {
			if _, ok := entries[key]; !ok {
				return nil, fmt.Errorf("language %s is missing key %q", language, key)
			}
		}
		for key := range entries {
			if _, ok := baseline[key]; !ok {
				return nil, fmt.Errorf("language %s contains unexpected key %q", language, key)
			}
		}
		for key, value := range entries {
			if !reflect.DeepEqual(formatDirectives(baseline[key]), formatDirectives(value)) {
				return nil, fmt.Errorf("language %s key %q contains mismatched format placeholders", language, key)
			}
		}
	}

	return &Catalog{messages: messages}, nil
}

// ResolveLanguage accepts only explicitly supported values and defaults to Chinese.
func ResolveLanguage(queryLanguage, cookieLanguage string) string {
	if language, ok := normalizeLanguage(queryLanguage); ok {
		return language
	}
	if language, ok := normalizeLanguage(cookieLanguage); ok {
		return language
	}
	return DefaultLanguage
}

// IsSupported reports whether the exact language identifier is supported.
func IsSupported(language string) bool {
	_, ok := normalizeLanguage(language)
	return ok
}

// SupportedLanguages returns a copy of the supported language identifiers.
func SupportedLanguages() []string {
	return append([]string(nil), languages...)
}

// LanguageURL returns the current local URL with a validated language query value.
func LanguageURL(current *url.URL, language string) string {
	resolved, ok := normalizeLanguage(language)
	if !ok {
		resolved = DefaultLanguage
	}
	if current == nil {
		return "?lang=" + url.QueryEscape(resolved)
	}
	copyURL := *current
	query := copyURL.Query()
	query.Set("lang", resolved)
	copyURL.RawQuery = query.Encode()
	return copyURL.RequestURI()
}

// NewLocalizer creates a localizer from the active catalog.
func NewLocalizer(language string) *Localizer {
	resolved, ok := normalizeLanguage(language)
	if !ok {
		resolved = DefaultLanguage
	}
	return &Localizer{catalog: activeCatalog.Load(), language: resolved}
}

// Localizer creates a localizer from a catalog without mutating global state.
func (c *Catalog) Localizer(language string) *Localizer {
	resolved, ok := normalizeLanguage(language)
	if !ok {
		resolved = DefaultLanguage
	}
	return &Localizer{catalog: c, language: resolved}
}

// Language returns the normalized language identifier.
func (l *Localizer) Language() string {
	if l == nil {
		return DefaultLanguage
	}
	return l.language
}

// T translates a key and falls back to Chinese, then to the key itself.
func (l *Localizer) T(key string, args ...interface{}) string {
	message := key
	found := false
	if l != nil && l.catalog != nil {
		if entries, ok := l.catalog.messages[l.language]; ok {
			if translated, exists := entries[key]; exists {
				message = translated
				found = true
			}
		}
		if !found {
			if translated, exists := l.catalog.messages[DefaultLanguage][key]; exists {
				message = translated
			}
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(message, args...)
	}
	return message
}

// formatDirectives returns fmt-style placeholders while ignoring escaped %%.
func formatDirectives(message string) []string {
	directives := make([]string, 0)
	for index := 0; index < len(message); index++ {
		if message[index] != '%' {
			continue
		}
		if index+1 < len(message) && message[index+1] == '%' {
			index++
			continue
		}
		start := index
		for index++; index < len(message); index++ {
			if strings.ContainsRune("bcdoOqxXUeEfFgGspvtT", rune(message[index])) {
				directives = append(directives, message[start:index+1])
				break
			}
		}
	}
	return directives
}

func normalizeLanguage(language string) (string, bool) {
	switch language {
	case DefaultLanguage:
		return DefaultLanguage, true
	case EnglishLanguage:
		return EnglishLanguage, true
	default:
		return "", false
	}
}
