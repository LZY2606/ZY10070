package api

import (
	"io/fs"
	"net/http"
)

// webRoot returns the embedded browser assets without their "web" prefix.
func webRoot() http.FileSystem {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}
