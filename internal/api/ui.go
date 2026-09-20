package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui_static
var uiFS embed.FS

// UI serves the embedded browser interface at /.
func UI() http.Handler {
	sub, err := fs.Sub(uiFS, "ui_static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
