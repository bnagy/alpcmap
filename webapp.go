package main

import (
	"log"
	"net/http"
	"strings"
)

// Serve serves our simple app
func Serve(procs []*Process) error {

	pageBytes, err := RenderGraph(procs)

	if err == nil {

		// Render the full function graph on /
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write(pageBytes)
		})

		// Handle /port/<objectid> "live"
		http.HandleFunc("/port/", func(w http.ResponseWriter, r *http.Request) {
			ff := strings.Split(r.RequestURI, "/")
			if len(ff) < 2 {
				http.Error(w, "trying to trick old kingy?", 500)
				return
			}

			if portDetail, err := GetPortDetail(ff[2]); err == nil {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(portDetail))
			} else {
				http.Error(w, err.Error(), 500)
			}
		})

		log.Println("Serving at http://localhost:8080")
		return http.ListenAndServe(":8080", nil)
	}
	return err

}
