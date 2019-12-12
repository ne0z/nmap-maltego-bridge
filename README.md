Nmap executable wrapper for Golang
----

```go
hosts, err := nmap.ScanOpenTcpPorts("192.168.1.0/24", "22")
fmt.Println(hosts)
```

this has heavy changes from upstream, since I needed it to be able to run as non-root and generate special output not just port and service..
I use this with my https://github.com/ChrisFernandez/maltego-nmap  maltego-nmap plugin
