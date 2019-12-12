package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
)

func scanOpenTcpPorts(subnet string, ports string) (io.Reader, error) {
	c := exec.Command("/usr/local/bin/nmap", "-oX", "-", "-sV", subnet, "--open")
	cout, cerr := c.Output()
	if cerr != nil {
		return nil, fmt.Errorf(cerr.Error())
	}

	return bytes.NewReader(cout), nil
}

func openXml(filename string) (io.Reader, error) {
	return os.Open(filename)
}

type NmapRun struct {
	XMLName xml.Name `xml:nmaprun"`
	Hosts   []Host   `xml:"host"`
}

type Host struct {
	XMLName xml.Name `xml:"host"`
	Ports   []Port   `xml:"ports>port"`
}

type Port struct {
	XMLName  xml.Name `xml:"port"`
	Protocol string   `xml:"protocol,attr"`
	PortId   int      `xml:"portid,attr"`
	Service  Service  `xml:"service"`
}

type Service struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Ostype  string   `xml:"ostype,attr"`
}

func parseXml(reader io.Reader) (hosts []HostScan, err error) {

	doc := NmapRun{}

	dec := xml.NewDecoder(reader)
	derr := dec.Decode(&doc)
	if derr != nil {
		return hosts, derr
	}

	for i := 0; i < len(doc.Hosts); i++ {
		scan := HostScan{}
		port := doc.Hosts[i]
		for p := 0; p < len(port.Ports); p++ {
			scan.HostPort = port.Ports[p].PortId
			scan.PortProto = port.Ports[p].Protocol
			scan.ServiceName = port.Ports[p].Service.Name
			scan.ServiceBanner = port.Ports[p].Service.Product
			//fmt.Println("Port: " + port.Ports[p].PortId)
			//fmt.Println("Protocol: " + port.Ports[p].Protocol)
			//fmt.Println("Name: " + port.Ports[p].Service.Name)
			//fmt.Println("Product: " + port.Ports[p].Service.Product)
			hosts = append(hosts, scan)
		}
	}

	return
}

type HostScan struct {
	HostPort      int
	PortProto     string
	ServiceName   string
	ServiceBanner string
}

func ScanOpenTcpPorts(subnet, ports string) (hosts []HostScan, err error) {
	reader, rerr := scanOpenTcpPorts(subnet, ports)
	if rerr != nil {
		return hosts, rerr
	}
	return parseXml(reader)
}
