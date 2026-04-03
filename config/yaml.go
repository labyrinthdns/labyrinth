package config

import "strings"

// parseYAML reads a simplified YAML file with up to 3-level nesting and array support.
// Returns a map of dot-separated keys → values.
// Examples: "server.listen_addr" → "0.0.0.0:53", "security.rate_limit.enabled" → "true"
func parseYAML(data []byte) (map[string]string, error) {
	result := make(map[string]string)
	var sections []string // stack of section names
	var lastKey string    // full key of the last key-value or section for array collection
	prevIndent := -1

	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 {
		// Accept UTF-8 BOM-prefixed files (common on Windows editors).
		lines[0] = strings.TrimPrefix(lines[0], "\ufeff")
	}
	for _, line := range lines {
		// Strip comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "" {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		content := strings.TrimSpace(trimmed)

		// Pop sections when indent decreases
		if indent <= prevIndent && len(sections) > 0 {
			// Calculate how many levels to pop
			targetDepth := indent / 2 // assuming 2-space indent
			for len(sections) > targetDepth {
				sections = sections[:len(sections)-1]
			}
		}

		// Array item: "- value"
		if strings.HasPrefix(content, "- ") {
			value := strings.TrimSpace(strings.TrimPrefix(content, "- "))
			value = strings.Trim(value, "\"'")
			if lastKey != "" && value != "" {
				if existing, ok := result[lastKey]; ok && existing != "" {
					result[lastKey] = existing + "," + value
				} else {
					result[lastKey] = value
				}
			}
			continue
		}

		// Key: value or section header
		if strings.Contains(content, ":") {
			parts := strings.SplitN(content, ":", 2)
			key := strings.TrimSpace(parts[0])
			value := ""
			if len(parts) == 2 {
				value = strings.TrimSpace(parts[1])
				value = strings.Trim(value, "\"'")
			}

			// Build full key from section stack
			fullKey := key
			if len(sections) > 0 {
				fullKey = strings.Join(sections, ".") + "." + key
			}

			if value == "" {
				// Section header or key awaiting array values
				sections = append(sections, key)
				// Also track as lastKey for array collection
				lastKey = fullKey
				result[fullKey] = ""
				prevIndent = indent
			} else {
				result[fullKey] = value
				lastKey = fullKey
				prevIndent = indent
			}
		}
	}

	return result, nil
}
