package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"time"
)

type ProtocolVersion uint8

const (
	IPv4 ProtocolVersion = 4
	IPv6 ProtocolVersion = 6
)

type Port uint16

type Packet struct {
	Time time.Time // Packet send/receive time

	Uid int32 // App uid

	Version ProtocolVersion // Protocol version

	Data []byte // Packet data

	Protocol layers.IPProtocol // Protocol

	SrcIP string // Source IP
	DstIP string // Destination IP

	SrcPort Port //Source Port
	DstPort Port //Destination Port

	DnsRecords []DnsRecord //DNS answer
}

type DnsRecord struct {
	Qname      string
	Aname      string
	Cname      string
	Hinfo      string
	Ip         string
	Rcode      uint8
	AnswerType layers.DNSType
}

type Decoder struct {
	ip4        layers.IPv4
	ip6        layers.IPv6
	tcp        layers.TCP
	udp        layers.UDP
	icmp4      layers.ICMPv4
	icmp6      layers.ICMPv6
	dns        layers.DNS
	payload    gopacket.Payload
	decoded    []gopacket.LayerType
	ipv4Parser *gopacket.DecodingLayerParser
	ipv6Parser *gopacket.DecodingLayerParser
	dnsParser  *gopacket.DecodingLayerParser
	defragger  *ip4defrag.IPv4Defragmenter
}

func NewDecoder() *Decoder {
	decoder := Decoder{}
	decoder.decoded = make([]gopacket.LayerType, 0, 10)
	decoder.ipv4Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &decoder.ip4, &decoder.tcp, &decoder.udp, &decoder.icmp4, &decoder.payload)
	decoder.ipv4Parser.IgnoreUnsupported = true
	decoder.ipv6Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &decoder.ip6, &decoder.tcp, &decoder.udp, &decoder.icmp6, &decoder.payload)
	decoder.ipv6Parser.IgnoreUnsupported = true
	decoder.dnsParser = gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, &decoder.dns)
	decoder.dnsParser.IgnoreUnsupported = true
	decoder.defragger = ip4defrag.NewIPv4Defragmenter()
	return &decoder
}

func (p *Packet) Decode(dnsCryptPort Port, torDnsPort Port, decoder *Decoder) error {

	payload, err := p.decodeIPv4or6(decoder)
	if err != nil {
		return err
	}

	if (p.SrcPort == dnsCryptPort || p.SrcPort == torDnsPort) && payload != nil {
		err := p.decodeDNS(payload, decoder)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Packet) Reset() {
	p.Time = time.UnixMilli(0)
	p.Uid = -1
	p.Version = 0
	p.Data = nil
	p.Protocol = 0
	p.SrcIP = ""
	p.DstIP = ""
	p.SrcPort = 0
	p.DstPort = 0
	p.DnsRecords = nil
}

// Decode a raw v4 or v6 IP packet.
func (p *Packet) decodeIPv4or6(decoder *Decoder) (gopacket.Payload, error) {
	version := p.Data[0] >> 4
	switch version {
	case 4:
		return decodeIPv4(p, decoder)
	case 6:
		return decodeIPv6(p, decoder)
	}
	return nil, nil
}

func decodeIPv4(p *Packet, decoder *Decoder) (gopacket.Payload, error) {
	err := decoder.ipv4Parser.DecodeLayers(p.Data, &decoder.decoded)
	if err != nil {
		return nil, err
	}
	for _, typ := range decoder.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			err = handleIPv4(p, decoder)
		case layers.LayerTypeTCP:
			return handleTcp(p, decoder), nil
		case layers.LayerTypeUDP:
			return handleUdp(p, decoder), nil
		case layers.LayerTypeICMPv4:
			handleIcmp4(p)
		}
	}

	return nil, err
}

func decodeIPv6(p *Packet, decoder *Decoder) (gopacket.Payload, error) {
	err := decoder.ipv6Parser.DecodeLayers(p.Data, &decoder.decoded)
	if err != nil {
		return nil, err
	}
	for _, typ := range decoder.decoded {
		switch typ {
		case layers.LayerTypeIPv6:
			handleIPv6(p, decoder)
		case layers.LayerTypeTCP:
			return handleTcp(p, decoder), nil
		case layers.LayerTypeUDP:
			return handleUdp(p, decoder), nil
		case layers.LayerTypeICMPv6:
			handleIcmp6(p)
		}
	}

	return nil, err
}

func handleIPv4(p *Packet, decoder *Decoder) error {
	newipv4, err := decoder.defragger.DefragIPv4(&decoder.ip4)

	if err != nil {
		return err
	} else if newipv4 == nil {
		return err // packet fragment, we don't have whole packet yet.
	}

	p.Version = IPv4
	p.SrcIP = newipv4.SrcIP.String()
	p.DstIP = newipv4.DstIP.String()

	return err
}

func handleIPv6(p *Packet, decoder *Decoder) {
	p.Version = IPv6
	p.SrcIP = decoder.ip6.SrcIP.String()
	p.DstIP = decoder.ip6.DstIP.String()
}

func handleTcp(p *Packet, decoder *Decoder) gopacket.Payload {
	p.Protocol = layers.IPProtocolTCP
	p.SrcPort = Port(decoder.tcp.SrcPort)
	p.DstPort = Port(decoder.tcp.DstPort)
	return decoder.payload
}

func handleUdp(p *Packet, decoder *Decoder) gopacket.Payload {
	p.Protocol = layers.IPProtocolUDP
	p.SrcPort = Port(decoder.udp.SrcPort)
	p.DstPort = Port(decoder.udp.DstPort)
	return decoder.payload
}

func handleIcmp4(p *Packet) {
	p.Protocol = layers.IPProtocolICMPv4
}

func handleIcmp6(p *Packet) {
	p.Protocol = layers.IPProtocolICMPv6
}

func (p *Packet) decodeDNS(data []byte, decoder *Decoder) error {

	if err := decoder.dnsParser.DecodeLayers(data[:], &decoder.decoded); err != nil {
		return err
	} else {
		p.DnsRecords = make([]DnsRecord, 0)
		for _, answer := range decoder.dns.Answers {

			questions := ""
			for j, question := range decoder.dns.Questions {
				questions += string(question.Name)
				if j != len(decoder.dns.Questions)-1 {
					questions += ","
				}
			}

			ip := ""
			if answer.IP != nil {
				ip = answer.IP.String()
			}

			p.DnsRecords = append(p.DnsRecords, DnsRecord{
				questions,
				string(answer.Name),
				string(answer.CNAME),
				string(answer.TXT),
				ip,
				uint8(decoder.dns.ResponseCode),
				answer.Type})
		}
	}

	return nil
}
