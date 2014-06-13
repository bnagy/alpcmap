package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os/exec"
	"regexp"
	"strings"
	"text/template"
)

var warnedBadRegex bool

func everyoneColor() string {
	if *bad1dea {
		return fmt.Sprintf("#%X", rand.Uint32())
	}
	return "#33FF33"
}

func tokenColor(proc Process) string {
	match, err := regexp.MatchString(*highlightRegex, proc.Token.SID)
	if match && err == nil {
		return "#33FF33"
	}
	if err != nil && !warnedBadRegex {
		log.Printf("Warning: Bad Highlight Regexp \"%v\": %v", *highlightRegex, err)
		warnedBadRegex = true
	}
	return "#CCCCCC"
}

func escapeName(name string) string {
	name = strings.Replace(name, `\`, `\\`, -1)
	// Replace the curly so graphviz can parse the dot. It gets unreplaced in
	// the generated HTML after the render.
	name = strings.Replace(name, `{`, `\{`, -1)
	name = strings.Replace(name, `}`, `\}`, -1)
	return name
}

var portTempl = `    {{.Label}} [shape=plaintext,label=<
		<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
		  <TR>
		    <TD PORT="head" BGCOLOR="{{. | tokenColor}}">{{.Image}}</TD>
		  </TR>
		  <TR>
		    <TD BGCOLOR="{{. | tokenColor}}">{{.Token.SID}}</TD>
		  </TR>
		  {{if eq (. | tokenColor) "#CCCCCC"}}
		  {{with .Ports}}{{range .}}<TR>
		    <TD HREF="/port/{{.ObjectID}}" PORT="{{.ObjectID}}" BGCOLOR="#CCCCCC" >{{.Name | escapeName}}</TD>
		  </TR>{{end}}{{end}}
		  {{else}}
		  {{with .Ports}}{{range .}}<TR>
		    <TD HREF="/port/{{.ObjectID}}" PORT="{{.ObjectID}}" {{if .Everyone}}BGCOLOR="{{everyoneColor}}"{{else}}BGCOLOR="#FF3333"{{end}}>{{.Name | escapeName}}</TD>
		  </TR>{{end}}{{end}}
		  {{end}}
		</TABLE>>];

`

var graphHeader = `digraph alpcmap {
	node [shape=record, fontname="Monaco"];
	edge [dir=none];
	graph [overlap=false, splines=true];


`

func render(in, out *bytes.Buffer) error {
	cmd := exec.Command(*graphType, "-Tsvg")
	cmd.Stdin = in
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return err
	}

	p := out.Bytes()
	// Unreplace escaped {}
	p = bytes.Replace(p, []byte(`\{`), []byte(`{`), -1)
	p = bytes.Replace(p, []byte(`\}`), []byte(`}`), -1)

	if i := bytes.Index(p, []byte("<svg")); i >= 0 {
		out.Reset()
		out.Write(p[i:])
		return nil
	}
	return errors.New("<svg not found")

}

func formatConn(c ALPCConn) string {
	return fmt.Sprintf("%s:%s", c.ProcessObject, c.PortObject)
}

// RenderGraph shells out to graphviz to parse the dot and generate HTML/SVG
func RenderGraph(procs []*Process) ([]byte, error) {

	log.Println("Rendering Graph...")
	var in, out bytes.Buffer
	var err error

	fmt.Fprintf(&in, graphHeader)

	portTemplate := template.New("port template")
	portTemplate = portTemplate.Funcs(
		template.FuncMap{
			"everyoneColor": everyoneColor,
			"tokenColor":    tokenColor,
			"escapeName":    escapeName,
		},
	)

	portTemplate, err = portTemplate.Parse(portTempl)
	if err != nil {
		log.Fatalf("[FATAL] error parsing template: %v", err)
	}

	for _, proc := range procs {
		// Dump the nodes first, which seems to establish the rankings better
		err = portTemplate.Execute(&in, proc)
		if err != nil {
			log.Fatalf("[FATAL] error executing template: %v", err)
		}

	}

	for _, proc := range procs {
		// Now the edges.
		for _, conn := range proc.ALPCConnections {
			fmt.Fprintf(&in, " %s:<head> -> %s;\n", proc.Label, formatConn(conn))
		}

	}
	in.WriteString("}")
	if *debug {
		ioutil.WriteFile("raw.dot", in.Bytes(), 0777)
	}

	err = render(&in, &out)
	log.Println("Rendered.")
	return out.Bytes(), err
}
