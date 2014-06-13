package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

var endpoint = flag.String("c", "http://localhost:4567/debugger", "API Endpoint to connect to")
var debug = flag.Bool("d", false, "Enable debug mode")
var bad1dea = flag.Bool("0x", false, "Enable pretty colors")
var graphType = flag.String("g", "twopi", "Graphviz command execute to generate graph")
var highlightRegex = flag.String("h", `SYSTEM`, "Highlight ports matching this regex")
var textMode = flag.Bool("t", false, "Dump matching ports in plaintext")

var buf bytes.Buffer

// Request will be marshalled to JSON to make a request to the remote debugger
type Request struct {
	Method string        `json:"method"`
	Args   []interface{} `json:"args"`
}

// ACE is an Access Control Entry
type ACE struct {
	Type string
	Mask uint
	SID  string
}

// ALPCPort holds selected ALPC port information
type ALPCPort struct {
	ObjectID string
	Name     string
	DACL     []ACE
	Everyone bool
}

// ALPCConn represents an ALPC connection to another process / ALPC port
type ALPCConn struct {
	ProcessObject string
	PortObject    string
}

// ProcessToken just holds the SID string at this point
type ProcessToken struct {
	SID string
}

// Process contains the output of the !process command for a single process
type Process struct {
	SessionID       int
	Cid             uint64
	Peb             uint64
	ParentCid       uint64
	DirBase         uint64
	ObjectTable     uint64
	HandleCount     uint64
	Image           string
	Label           string
	Token           ProcessToken
	Ports           []ALPCPort
	ALPCConnections []ALPCConn
}

// RunMethod runs a remote method via a POST/JSON API
func RunMethod(meth string, args []interface{}) (interface{}, error) {

	buf.Reset()
	err := json.NewEncoder(&buf).Encode(
		Request{
			Method: meth,
			Args:   args,
		},
	)

	if err != nil {
		return []interface{}{}, err
	}

	resp, err := http.Post(*endpoint, "application/json", &buf)
	if err != nil {
		return []interface{}{}, err
	}

	defer resp.Body.Close()

	var result interface{}
	e := json.NewDecoder(resp.Body).Decode(&result)
	return result, e

}

// Execute runs an arbitrary command string (as if typed into windbg) and
// returns the result
func Execute(command string) (string, error) {

	res, err := RunMethod("execute", []interface{}{command})
	if err != nil {
		return "", err
	}

	return res.(string), err
}

// AttachLocalKernel tells the remote to attach as a local kernel debugger (
// like lkd )
func AttachLocalKernel() (bool, error) {

	res, err := RunMethod("attach_local_kernel", []interface{}{})
	if err != nil {
		return false, err
	}
	return res.(bool), nil
}

// WaitForEvent asks the remote to wait for the next debugger event. Blocking.
func WaitForEvent(timeout int) error {

	_, err := RunMethod("wait_for_event", []interface{}{timeout})
	return err
}

func main() {

	flag.Parse()

	log.Printf("Connecting to remote debugger at %s\n", *endpoint)
	res, err := AttachLocalKernel()
	if res == false || err != nil {
		log.Fatalf("[FATAL] Unable to connect to %s: %v", *endpoint, err)
	}
	WaitForEvent(-1)
	log.Println("Connected!")
	procs := GetProcs()

	log.Println("Got process list, running ALPC queries...")
	for i, proc := range procs {

		GetProcPorts(proc)

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
	err = Serve(procs)
	log.Fatal(err)

}
