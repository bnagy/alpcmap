package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/bnagy/alpcbuggery"
	"log"
	"regexp"
)

var endpoint = flag.String("c", "http://localhost:4567/debugger", "API Endpoint to connect to")
var port = flag.Int("p", 8000, "Local port to serve on")
var debug = flag.Bool("d", false, "Enable debug mode")
var bad1dea = flag.Bool("0x", false, "Enable pretty colors")
var graphType = flag.String("g", "twopi", "Graphviz command execute to generate graph")
var highlightRegex = flag.String("h", `SYSTEM`, "Highlight ports matching this regex")
var textMode = flag.Bool("t", false, "Dump matching ports in plaintext")

var buf bytes.Buffer

func main() {

	flag.Parse()

	log.Printf("Connecting to remote debugger at %s\n", *endpoint)
	debugger := alpcbuggery.NewDebugger(*endpoint)
	res, err := debugger.AttachLocalKernel()
	if res == false || err != nil {
		log.Fatalf("[FATAL] Unable to connect to %s: %v", *endpoint, err)
	}
	debugger.WaitForEvent(-1)
	log.Println("Connected!")
	procs := debugger.GetProcs()

	log.Println("Got process list, running ALPC queries...")
	for i, proc := range procs {

		debugger.GetProcPorts(proc)

		if *textMode {
			match, err := regexp.MatchString(*highlightRegex, proc.Token.SID)
			if match && err == nil {
				for _, port := range proc.Ports {
					if port.Everyone {
						fmt.Printf("%s: %s\n", proc.Image, port.Name)
					}
				}
			}

		} else {
			fmt.Printf("\r(%d of %d)", i+1, len(procs))
		}

	}
	fmt.Print("\n")
	err = Serve(debugger, procs, *port)
	log.Fatal(err)

}
