package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
)

var portsCreated = regexp.MustCompile(`^Ports created by the process [0-9a-f]+:`)
var portsConnected = regexp.MustCompile(`^Ports the process [0-9a-f]+ is connected to:`)
var portValid = regexp.MustCompile(`[a-f0-9]{8,16}\('.*?'\)`)
var portError = regexp.MustCompile("Error querying")
var aceType = regexp.MustCompile(`^->Dacl    : ->Ace\[\d+\]: ->AceType:`)

func mustParseUint(s string, base, bitSize int) (n uint64) {
	n, err := strconv.ParseUint(s, base, bitSize)
	if err != nil {
		panic(err)
	}
	return
}

// GetToken gets the SID for the default process token. The process could be
// impersonating, so this is not 100% accurate.
func GetToken(tokID string) (pTok ProcessToken, e error) {
	tokInfo, _ := Execute(fmt.Sprintf("!token /n %s", tokID))
	scanner := bufio.NewScanner(strings.NewReader(tokInfo))

	scanner.Scan()
	if strings.Fields(scanner.Text())[0] != "_TOKEN" {
		return ProcessToken{}, errors.New(scanner.Text())
	}

	for scanner.Scan() {
		// Looking for:
		// User: S-1-5-21-840331635-3941572184-3711098457-1000 (User: WIN-5E72NJ6H2JO\ben)
		ff := strings.Fields(scanner.Text())
		if ff[0] == "User:" {
			user := ""
			switch ff[2] {
			default:
				user = ff[1]
			case "(User:":
				user = strings.Join(ff[3:], " ")
			case "(Well": // (Well Known Group: XYZ\Blah)
				user = strings.Join(ff[5:], " ")
			}
			user = strings.Replace(user, `\`, `\\`, -1)
			pTok = ProcessToken{SID: strings.TrimRight(user, ")")}
			return
		}
	}
	e = errors.New("string User: not found in !token output")
	return
}

// GetProcs gets a list of all processes using the "!process 0 0" command
func GetProcs() (procList []*Process) {

	procs, _ := Execute("!process 0 1")
	scanner := bufio.NewScanner(strings.NewReader(procs))

	scanner.Scan() // header line: **** NT ACTIVE PROCESS DUMP ****

	for scanner.Scan() {

		// PROCESS fffffa8030cc6040
		//   SessionID: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
		//   DirBase: 00187000  ObjectTable: fffff8a0000017e0  HandleCount: 496.
		//   Image: System
		//

		var p Process
		p.Label = strings.Fields(scanner.Text())[1] // PROCESS fffffa8030cc6040

		scanner.Scan() //   SessionID: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
		ff := strings.Fields(scanner.Text())
		if s, err := strconv.Atoi(ff[1]); err == nil {
			p.SessionID = s
		} else {
			p.SessionID = -1
		}
		p.Cid = mustParseUint(ff[3], 16, 0)
		p.Peb = mustParseUint(ff[5], 16, 0)
		p.ParentCid = mustParseUint(ff[7], 16, 0)

		scanner.Scan() //   DirBase: 00187000  ObjectTable: fffff8a0000017e0  HandleCount: 496.
		ff = strings.Fields(scanner.Text())
		p.DirBase = mustParseUint(ff[1], 16, 0)
		p.ObjectTable = mustParseUint(ff[3], 16, 0)
		p.HandleCount = mustParseUint(strings.TrimRight(ff[5], "."), 10, 0)

		scanner.Scan() //   Image: System
		p.Image = strings.Fields(scanner.Text())[1]

		procList = append(procList, &p)

		for scanner.Text() != "" {
			ff = strings.Fields(scanner.Text())
			if ff[0] == "Token" {
				tok, err := GetToken(ff[1])
				if err != nil {
					log.Fatalf("fail to get token info for %v: %v", tok, err)
				}
				p.Token = tok
			}
			scanner.Scan()
		}
	}
	return
}

// GetDACL gets the DACL for an ALPC port by parsing the SecurityDescriptor in
// the object header
func GetDACL(port *ALPCPort) {

	// Phase 1 - Get the Object entry for the port
	objInfo, _ := Execute(fmt.Sprintf("!object %s", port.ObjectID))
	// Object: fffffa803218e170  Type: (fffffa8030cf7080) ALPC Port
	//    ObjectHeader: fffffa803218e140 (new version)
	//    HandleCount: 1  PointerCount: 17
	//    Directory Object: fffff8a000a2db90  Name: plugplay
	scanner := bufio.NewScanner(strings.NewReader(objInfo))
	scanner.Scan()
	scanner.Scan()
	ff := strings.Fields(scanner.Text())
	if ff[0] != "ObjectHeader:" {
		log.Fatalf("no ObjectHeader while parsing !object %s [%s]", port.ObjectID, scanner.Text())
	}

	// Phase 2 - Parse the ObjectHeader using dt
	typeInfo, _ := Execute(fmt.Sprintf("dt nt!_OBJECT_HEADER %s", ff[1]))
	// NEW VERSION - don't know if this code works with the old?
	// +0x000 PointerCount     : 0n17
	// +0x008 HandleCount      : 0n1
	// +0x008 NextToFree       : 0x00000000`00000001 Void
	// +0x010 Lock             : _EX_PUSH_LOCK
	// +0x018 TypeIndex        : 0x24 '$'
	// +0x019 TraceFlags       : 0 ''
	// +0x01a InfoMask         : 0xe ''
	// +0x01b Flags            : 0x40 '@'
	// +0x020 ObjectCreateInfo : 0xfffff800`02c54940 _OBJECT_CREATE_INFORMATION
	// +0x020 QuotaBlockCharged : 0xfffff800`02c54940 Void
	// +0x028 SecurityDescriptor : 0xfffff8a0`00f274cd Void
	// +0x030 Body             : _QUAD
	scanner = bufio.NewScanner(strings.NewReader(typeInfo))
	addr := ""
	for scanner.Scan() {
		ff := strings.Fields(scanner.Text())
		if ff[1] == "SecurityDescriptor" {
			addr = ff[3]
			// FIXME 64 bit only - this is 'masking' the last 4 bits
			// but for x86 need to mask only last 3
			addr = addr[:len(addr)-1] + "0"
			break
		}
	}
	if addr == "" {
		// Can't find it :(
		return
	}

	// Phase 3 - Use the !sd extension to dump the Security Descriptor
	// ->Revision: 0x1
	// ->Sbz1    : 0x0
	// ->Control : 0x8804
	//             SE_DACL_PRESENT
	//             SE_SACL_AUTO_INHERITED
	//             SE_SELF_RELATIVE
	// ->Owner   : S-1-5-18 (Well Known Group: NT AUTHORITY\SYSTEM)
	// ->Group   : S-1-5-18 (Well Known Group: NT AUTHORITY\SYSTEM)
	// ->Dacl    :
	// ->Dacl    : ->AclRevision: 0x2
	// ->Dacl    : ->Sbz1       : 0x0
	// ->Dacl    : ->AclSize    : 0x5c
	// ->Dacl    : ->AceCount   : 0x4
	// ->Dacl    : ->Sbz2       : 0x0
	// ->Dacl    : ->Ace[0]: ->AceType: ACCESS_ALLOWED_ACE_TYPE
	// ->Dacl    : ->Ace[0]: ->AceFlags: 0x0
	// ->Dacl    : ->Ace[0]: ->AceSize: 0x14
	// ->Dacl    : ->Ace[0]: ->Mask : 0x00030001
	// ->Dacl    : ->Ace[0]: ->SID: S-1-1-0 (Well Known Group: localhost\Everyone)

	// ->Dacl    : ->Ace[1]: ->AceType: ACCESS_ALLOWED_ACE_TYPE
	// [...more Dacls...]
	//
	// ->Sacl    :  is NULL
	sdInfo, _ := Execute(fmt.Sprintf("!sd %s 1", addr)) // 1 - enable friendly names
	scanner = bufio.NewScanner(strings.NewReader(sdInfo))
	for scanner.Scan() {
		if aceType.MatchString(scanner.Text()) {
			var ace ACE
			if strings.Fields(scanner.Text())[3] != "->AceType:" {
				log.Fatalf("error parsing SID output, wanted AceType line, got %s", scanner.Text())
			}
			ace.Type = strings.Fields(scanner.Text())[4]
			scanner.Scan() // ignore AceFlags
			scanner.Scan() // ignore AceSize
			scanner.Scan()
			ace.Mask = uint(mustParseUint(strings.Fields(scanner.Text())[5], 0, 0))
			scanner.Scan()
			ff := strings.Split(scanner.Text(), "(")
			if len(ff) != 2 {
				log.Fatalf("error parsing SID output, wanted SID line, got %s", scanner.Text())
			}
			ace.SID = strings.Trim(ff[1], ")")
			if match, _ := regexp.MatchString(`Everyone`, ace.SID); match {
				port.Everyone = true
			}
			port.DACL = append(port.DACL, ace)
		}
	}

}

// GetAbsPortPath walks an ALPC port back to the root of the kernel Object
// directory to obtain the full path
func GetAbsPortPath(port string) (absPath string) {
	stack := []string{}
	obj := port
	this := ""
	// Working backwards to the root, like this:
	// lkd> !object fffffa80352ea740 3
	// 	Object: fffffa80352ea740  Type: (fffffa8030d11080) ALPC Port
	//     ObjectHeader: fffffa80352ea710 (new version)
	//     HandleCount: 1  PointerCount: 4
	//     Directory Object: fffff8a000a4c450  Name: OLE8F8B8C095131496BB200263FA52C
	// lkd> !object fffff8a000a4c450 3
	// Object: fffff8a000a4c450  Type: (fffffa8030c64f30) Directory
	//     ObjectHeader: fffff8a000a4c420 (new version)
	//     HandleCount: 0  PointerCount: 72
	//     Directory Object: fffff8a0000046c0  Name: RPC Control
	// lkd> !object fffff8a0000046c0 3
	// Object: fffff8a0000046c0  Type: (fffffa8030c64f30) Directory
	//     ObjectHeader: fffff8a000004690 (new version)
	//     HandleCount: 0  PointerCount: 44
	//     Directory Object: 00000000  Name: \
	for this != `\` {

		objInfo, _ := Execute(fmt.Sprintf("!object %s 3", obj))
		scanner := bufio.NewScanner(strings.NewReader(objInfo))

		for i := 0; i < 4; i++ {
			scanner.Scan()
		}
		ff := strings.Fields(scanner.Text())
		if len(ff) < 5 || ff[0] != "Directory" || ff[3] != "Name:" {
			log.Fatalf("failed to get Directory / Name from: %s", scanner.Text())
		}

		obj = ff[2]
		this = strings.Join(ff[4:], " ")
		stack = append([]string{this}, stack...)
	}

	stack[0] = "" // Just to avoid \\ for the root dir
	absPath = strings.Join(stack, `\`)
	return

}

// GetPort gets port information for an ALPC port string from the "!alpc /lpp
// <process>" command
func GetPort(raw string) (port ALPCPort) {
	// fffffa8032129590('OLE16E02A5AAD974222920005479E7C')
	ss := strings.Split(raw, "(")
	port.ObjectID = ss[0]
	port.Name = GetAbsPortPath(port.ObjectID)
	GetDACL(&port)
	return
}

// GetPortDetail gets more detailed port information using the !alpc extension
func GetPortDetail(portID string) (detail string, e error) {

	log.Printf("Querying port %s", portID)

	detail, _ = Execute(fmt.Sprintf("!alpc /p %s", portID))
	if portError.MatchString(detail) {
		e = fmt.Errorf("error querying port %s: %v", portID, detail)
		return
	}

	conns, _ := Execute(fmt.Sprintf("!alpc /lpc %s", portID))
	if portError.MatchString(detail) {
		e = fmt.Errorf("error querying port %s: %v", portID, detail)
		return
	}

	detail = detail + "\n" + conns
	return
}

// GetProcPorts finds all ALPC ports and connections for a process object
// using "!alpc /lpp"
func GetProcPorts(proc *Process) {

	//
	// 	Ports created by the process fffffa80353c3060:
	//
	// 	fffffa8032129590('OLE16E02A5AAD974222920005479E7C') 0, 1 connections
	// 		fffffa8033c6fb80 0 -> fffffa803262f900 0 fffffa80321ac580('svchost.exe')
	//
	// Ports the process fffffa80353c3060 is connected to:
	//
	// 	fffffa8035261e60 0 -> fffffa8032059e60('ApiPort') 0 fffffa8032e68b30('csrss.exe')
	// 	fffffa80353ce070 0 -> fffffa8033c2a6b0('ThemeApiPort') 0 fffffa8032fd2b30('svchost.exe')
	// 	fffffa80365bb8c0 0 -> fffffa803211a5a0('lsasspirpc') 0 fffffa80320a3440('lsass.exe')
	// 	fffffa80365b2e60 0 -> fffffa8032174cf0('ntsvcs') 19 fffffa803207fb30('services.exe')

	alpcInfo, _ := Execute(fmt.Sprintf("!alpc /lpp %s", proc.Label))
	scanner := bufio.NewScanner(strings.NewReader(alpcInfo))

	for scanner.Scan() {

	preamble:
		// skip blank lines
		for {
			if portsCreated.MatchString(scanner.Text()) {
				break preamble
			}
			scanner.Scan()
		}

	ports:
		// get all ports hosted by this process
		for {
			if portsConnected.MatchString(scanner.Text()) {
				break ports
			}
			ff := strings.Fields(scanner.Text())
			if len(ff) == 0 || ff[len(ff)-1] != "connections" {
				scanner.Scan()
				continue
			}
			p := portValid.FindString(scanner.Text())
			if p == "" {
				log.Fatalf("parsing error: no connection port found in: %v", scanner.Text())
			}
			proc.Ports = append(proc.Ports, GetPort(p))
			scanner.Scan()
		}

		// edges:
		for scanner.Scan() {
			ff := strings.Fields(scanner.Text())
			// 	fffffa80353d9b90 0 -> fffffa8030d087e0('ApiPort') 0 fffffa8032ad2b30('csrss.exe')
			if len(ff) == 6 && ff[2] == "->" {
				owner := strings.Split(ff[5], "(")[0]
				dest := strings.Split(ff[3], "(")[0]
				proc.ALPCConnections = append(proc.ALPCConnections, ALPCConn{ProcessObject: owner, PortObject: dest})
			}
		}
	}
}
