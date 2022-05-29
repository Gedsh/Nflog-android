package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/gopacket/layers"
	"io"
	"net"
	"os"
	"strings"
)

const UnknownUid = -1
const EmptyIp = "0.0.0.0"

const (
	ProcTcp  = "/proc/net/tcp"
	ProcUdp  = "/proc/net/udp"
	ProcIcmp = "/proc/net/icmp"
)

func (p *Packet) TryFindUidInProcNet() error {

	var uid int32 = UnknownUid
	var err error = nil

	switch p.Protocol {
	case layers.IPProtocolTCP:
		uid, err = parseProcNet(ProcTcp, p)
	case layers.IPProtocolUDP:
		uid, err = parseProcNet(ProcUdp, p)
	case layers.IPProtocolICMPv4:
		uid, err = parseProcNet(ProcIcmp, p)
	}

	if err != nil {
		return err
	}

	if uid > 0 {
		p.Uid = uid
	}

	return nil
}

func parseProcNet(fileName string, p *Packet) (uid int32, err error) {

	file, err := os.Open(fileName)
	if err != nil {
		return UnknownUid, err
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "ERR Error closing file %s: %v\n", fileName, err)
		}
	}(file)

	var numberOfEntry int
	var localIpEncoded string
	var localPort int
	var remoteIpEncoded string
	var remotePort int
	var connectionState int
	var transmitQueue int
	var receiveQueue int
	var timerActive int
	var numberOfJiffiesUntilTimerExpires int
	var numberOfUnrecoveredRtoTimeouts int

	reader := bufio.NewReader(file)
	for {

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return UnknownUid, err
			}
		}

		_, err = fmt.Fscanf(
			strings.NewReader(line),
			"%d: %8s:%X %8s:%X %X %X:%X %X:%X %X %d",
			&numberOfEntry,
			&localIpEncoded,
			&localPort,
			&remoteIpEncoded,
			&remotePort,
			&connectionState,
			&transmitQueue,
			&receiveQueue,
			&timerActive,
			&numberOfJiffiesUntilTimerExpires,
			&numberOfUnrecoveredRtoTimeouts,
			&uid)
		if err != nil {
			continue
		}

		localIp, err := convertIpV4(localIpEncoded)
		if err != nil {
			return UnknownUid, err
		}

		remoteIp, err := convertIpV4(remoteIpEncoded)
		if err != nil {
			return UnknownUid, err
		}

		//_, _ = fmt.Fprintf(os.Stdout, "%s:%d %s:%d %d %d\n", localIp, localPort, remoteIp, remotePort, connectionState, uid)

		if p.SrcPort == Port(localPort) &&
			(p.DstPort == Port(remotePort) || remotePort == 0) &&
			(p.SrcIP == localIp || localIp == EmptyIp) &&
			(p.DstIP == remoteIp || remoteIp == EmptyIp) {
			return uid, nil
		}
	}

	return UnknownUid, err
}

func convertIpV4(s string) (string, error) {

	if len(s) > 8 {
		return "", errors.New("invalid length of hex string")
	}

	decoded, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}

	ipv4 := net.IPv4(decoded[3], decoded[2], decoded[1], decoded[0])

	return ipv4.String(), nil
}
