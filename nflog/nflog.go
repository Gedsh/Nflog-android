package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket/layers"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

const localhost = "127.0.0.1"
const noUid = -2
const defaultGroup = 100
const defaultDnsCryptPort = 5354
const defaultTorDnsPort = 5400
const noPrefix = ""

type ConfigFlags struct {
	ownUid       int32
	dnscryptPort Port
	torDNSPort   Port
	prefix       string
}

func main() {

	runtime.MemProfileRate = 0

	ownUid := flag.Int("ouid", noUid, "Host Application UID")
	dnscryptPort := flag.Int("dport", defaultDnsCryptPort, "DNSCrypt proxy port")
	torDNSPort := flag.Int("tport", defaultTorDnsPort, "Tor DNS proxy port")
	prefix := flag.String("prefix", noPrefix, "Nflog logs prefix")
	var nflogGroup = flag.Int("group", defaultGroup, "Nflog group")
	flag.Parse()

	flags := ConfigFlags{
		ownUid:       int32(*ownUid),
		dnscryptPort: Port(*dnscryptPort),
		torDNSPort:   Port(*torDNSPort),
		prefix:       *prefix,
	}

	// Send outgoing pings to nflog group 100
	// # sudo iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100

	config := nflog.Config{
		Group:    uint16(*nflogGroup),
		Copymode: nflog.CopyPacket,
		Bufsize:  1024}

	nf, err := nflog.Open(&config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stdout, "ERR Could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var decoder = NewDecoder()
	var packet = new(Packet)

	// Register your function to listen on nflog group
	err = nf.RegisterWithErrorFunc(ctx, getHookFunc(packet, decoder, &flags), getErrorFunc())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "ERR Failed to register hook function: %v\n", err)
		return
	}

	err = PidFileCreate()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "ERR Failed to create pid file: %v\n", err)
	}

	quitCh := make(chan os.Signal, 1)
	go signal.Notify(quitCh, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM, syscall.SIGQUIT)

	// Block till the signal
	<-quitCh

	err = PidFileRemove()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "ERR Failed to remove pid file: %v\n", err)
	}
}

func getHookFunc(packet *Packet, decoder *Decoder, flags *ConfigFlags) func(attrs nflog.Attribute) int {

	var savedUid int32
	var savedSrcIP string
	var savedSrcPort Port

	return func(attrs nflog.Attribute) int {
		if pref := attrs.Prefix; flags.prefix != noPrefix && (pref == nil || *pref != flags.prefix) {
			return 0
		}

		packet.Reset()

		if time := attrs.Timestamp; time != nil {
			packet.Time = *time
		}

		if uid := attrs.UID; uid != nil {
			packet.Uid = int32(*uid)
		}

		if payload := attrs.Payload; payload != nil {

			packet.Data = *payload

			if err := packet.Decode(flags.dnscryptPort, flags.torDNSPort, decoder); err != nil {
				_, _ = fmt.Fprintln(os.Stdout, "ERR Error decoding some part of the packet:", err)
			}

			if records := packet.DnsRecords; records != nil && len(records) > 0 {
				for _, record := range records {
					if record.AnswerType != layers.DNSTypePTR {
						_, _ = fmt.Fprintf(os.Stdout,
							"DNS QNAME:%s ANAME:%s CNAME:%s HINFO:%s RCODE:%d IP:%s\n",
							record.Qname, record.Aname, record.Cname, record.Hinfo, record.Rcode, record.Ip)
					}
				}
			} else if (flags.ownUid == noUid || packet.Uid != flags.ownUid) &&
				packet.SrcIP != localhost && packet.DstIP != localhost && packet.DstPort != 53 &&
				(packet.SrcIP != packet.DstIP || packet.SrcPort != packet.DstPort) &&
				(packet.Uid != savedUid || packet.SrcIP != savedSrcIP || packet.SrcPort != savedSrcPort) {
				_, _ = fmt.Fprintf(os.Stdout,
					"PKT UID:%d %s SIP:%s SPT:%d DIP:%s DPT:%d\n",
					packet.Uid, packet.Protocol.String(), packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
				savedUid = packet.Uid
				savedSrcIP = packet.SrcIP
				savedSrcPort = packet.SrcPort
			}

		}

		return 0
	}
}

func getErrorFunc() func(e error) int {
	return func(e error) int {
		// Just log the error and return 0 to continue receiving packets
		if !strings.Contains(e.Error(), "no buffer space available") {
			_, _ = fmt.Fprintf(os.Stdout, "ERR Received error on hook: %v\n", e)
		}
		return 0
	}
}
