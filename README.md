alpcmap
=======

Connect to a JSON rBuggery stub to map Windows ALPC information

```
Usage of ./alpcmap:
  -0x=false: Enable pretty colors
  -c="http://localhost:4567/debugger": API Endpoint to connect to
  -d=false: Enable debug mode
  -g="twopi": Graphviz command execute to generate graph
  -h="SYSTEM": Highlight ports matching this regex
  -t=false: Dump matching ports in plaintext
 ```

TODO:
=======

Probably a lot

Screenshots
=======

Text Mode
----
```
$ ./alpcmap -c http://172.16.216.139:4567/debugger -d -t -h SYSTEM -g fdp
2014/06/13 12:12:37 Connecting to remote debugger at http://172.16.216.139:4567/debugger
2014/06/13 12:12:37 Connected!
2014/06/13 12:12:50 Got process list, running ALPC queries...
csrss.exe: \Windows\ApiPort
wininit.exe: \RPC Control\WMsgKRpc093C20
wininit.exe: \RPC Control\WindowsShutdown
csrss.exe: \Sessions\1\Windows\ApiPort
winlogon.exe: \RPC Control\WMsgKRpc095FC1
services.exe: \RPC Control\ntsvcs
services.exe: \RPC Control\LRPC-c96aaeeab0887ed04a
services.exe: \RPC Control\ubpmrpc
lsass.exe: \RPC Control\LRPC-f07a68951dc06a1ad8
lsass.exe: \RPC Control\audit
lsass.exe: \RPC Control\securityevent
lsass.exe: \RPC Control\LSARPC_ENDPOINT
lsass.exe: \RPC Control\lsapolicylookup
lsass.exe: \RPC Control\lsasspirpc
lsass.exe: \RPC Control\protected_storage
lsass.exe: \RPC Control\samss lpc
lsm.exe: \RPC Control\LRPC-b9caa281ff9ab82524
lsm.exe: \RPC Control\LSMApi
[...]
```

Web Interface
----
![Alt text](/screen1.png?raw=true "Web Interface")


BUGS
=======

Contributing
=======

Fork & pullreq

License
=======

BSD Style, See LICENSE file for details



