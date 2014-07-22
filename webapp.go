package main

import (
	"fmt"
	"github.com/bnagy/alpcbuggery"
	"log"
	"net/http"
	"strings"
)

// Serve serves our simple app
func Serve(debugger alpcbuggery.Debugger, procs []*alpcbuggery.Process, port int) error {

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

			if portDetail, err := debugger.GetPortDetail(ff[2]); err == nil {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(portDetail))
			} else {
				http.Error(w, err.Error(), 500)
			}
		})

		log.Printf("Serving at http://localhost:%v", port)
		return http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
	}
	return err

}
