package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
)

const UnknownUid = -1

const (
	ProcTcp = "/proc/net/tcp"
	ProcUdp = "/proc/net/udp"
)

var re = regexp.MustCompile(`^\s*\d+:\s+(?P<localIp>[\dA-F]+):(?P<localPort>[\dA-F]+)\s+(?P<remoteIp>[\dA-F]+):(?P<remotePort>[\dA-F]+)\s+[\dA-F]{2}\s+[\dA-F]+:[\dA-F]+\s+[\dA-F]+:[\dA-F]+\s+[\dA-F]+\s+(?P<uid>\d+)\s+.*$`)

func (p *Packet) TryFindUidInProcNet() error {

	uid, err := parseProcNet(ProcTcp, p)
	if err != nil {
		return err
	}

	if uid == UnknownUid {
		uid, err = parseProcNet(ProcUdp, p)
	}
	if err != nil {
		return err
	}

	if uid > 0 {
		p.Uid = uid
	}

	return nil
}

func parseProcNet(filename string, p *Packet) (uid int32, err error) {

	file, err := os.Open(filename)
	if err != nil {
		return UnknownUid, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "ERR Error closing file %s: %v\n", filename, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if re.MatchString(scanner.Text()) {
			matchedLocalIp := fmt.Sprintf("${%s}", re.SubexpNames()[1])
			matchedLocalPort := fmt.Sprintf("${%s}", re.SubexpNames()[2])
			matchedRemoteIp := fmt.Sprintf("${%s}", re.SubexpNames()[3])
			matchedRemotePort := fmt.Sprintf("${%s}", re.SubexpNames()[4])
			matchedUid := fmt.Sprintf("${%s}", re.SubexpNames()[5])

			localIp, err := convertIpV4(re.ReplaceAllString(scanner.Text(), matchedLocalIp))
			if err != nil {
				return UnknownUid, err
			}

			localPort, err := hex2dec(re.ReplaceAllString(scanner.Text(), matchedLocalPort))
			if err != nil {
				return UnknownUid, err
			}

			remoteIp, err := convertIpV4(re.ReplaceAllString(scanner.Text(), matchedRemoteIp))
			if err != nil {
				return UnknownUid, err
			}

			remotePort, err := hex2dec(re.ReplaceAllString(scanner.Text(), matchedRemotePort))
			if err != nil {
				return UnknownUid, err
			}

			uid, err := strconv.Atoi(re.ReplaceAllString(scanner.Text(), matchedUid))
			if err != nil {
				return UnknownUid, err
			}

			//_, _ = fmt.Fprintf(os.Stdout, "%s:%d %s:%d %d\n", localIp, localPort, remoteIp, remotePort, uid)

			if p.SrcPort == Port(localPort) && p.DstPort == Port(remotePort) &&
				p.SrcIP == localIp && p.DstIP == remoteIp {
				return int32(uid), nil
			}

		}
	}
	return UnknownUid, nil
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

func hex2dec(hex string) (int64, error) {
	dec, err := strconv.ParseInt(hex, 16, 32)
	if err != nil {
		return 0, err
	}
	return dec, nil
}
