package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed ui/dist/*
var uiFS embed.FS

// SPAHandler serves the embedded React SPA, falling back to index.html
// for client-side routing.
func SPAHandler() http.Handler {
	distFS, err := fs.Sub(uiFS, "ui/dist")
	if err != nil {
		// If dist doesn't exist (dev mode), serve a placeholder
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(placeholderHTML))
		})
	}

	fileServer := http.FileServer(http.FS(distFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// API and metrics paths are handled by other handlers
		if strings.HasPrefix(path, "/api/") || path == "/metrics" {
			http.NotFound(w, r)
			return
		}

		// Try to serve static file
		if path != "/" {
			// Check if file exists
			cleanPath := strings.TrimPrefix(path, "/")
			if f, err := distFS.Open(cleanPath); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		// Fall back to index.html for SPA routing
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

const placeholderHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Labyrinth DNS</title>
<style>
  body { font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #1A2744; color: #D4A843; }
  .c { text-align: center; }
  h1 { font-size: 2rem; margin-bottom: 0.5rem; }
  p { color: #8B7D6B; }
</style>
</head>
<body>
<div class="c">
  <h1>Labyrinth DNS Resolver</h1>
  <p>Dashboard is not built yet. Run: cd web/ui && npm run build</p>
</div>
</body>
</html>`
