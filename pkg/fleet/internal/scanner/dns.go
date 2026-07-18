package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	dnsTypeA   = 1
	dnsTypePTR = 12
	dnsTypeSRV = 33
)

type dnsQuestion struct {
	name  string
	type_ uint16
}

type dnsRecord struct {
	name    string
	type_   uint16
	address netip.Addr
	target  string
}

func buildDNSQuery(questions []dnsQuestion) ([]byte, error) {
	packet := make([]byte, 12)
	for _, question := range questions {
		encoded, err := encodeDNSName(question.name)
		if err != nil {
			return nil, err
		}
		packet = append(packet, encoded...)
		packet = binary.BigEndian.AppendUint16(packet, question.type_)
		packet = binary.BigEndian.AppendUint16(packet, 1)
	}
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(questions)))
	return packet, nil
}

func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	result := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS name %q", name)
		}
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	result = append(result, 0)
	if len(result) > 255 {
		return nil, fmt.Errorf("DNS name is too long: %q", name)
	}
	return result, nil
}

func parseDNSRecords(packet []byte) ([]dnsRecord, error) {
	if len(packet) < 12 {
		return nil, errors.New("DNS packet is shorter than its header")
	}
	offset := 12
	questionCount := int(binary.BigEndian.Uint16(packet[4:6]))
	if questionCount > (len(packet)-offset)/5 { // Root name plus type and class.
		return nil, errors.New("DNS question count exceeds packet size")
	}
	for range questionCount {
		_, next, err := decodeDNSName(packet, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+4 > len(packet) {
			return nil, errors.New("truncated DNS question")
		}
		offset += 4
	}

	recordCount := int(binary.BigEndian.Uint16(packet[6:8])) +
		int(binary.BigEndian.Uint16(packet[8:10])) +
		int(binary.BigEndian.Uint16(packet[10:12]))
	if recordCount > (len(packet)-offset)/11 { // Root name plus fixed record fields.
		return nil, errors.New("DNS record count exceeds packet size")
	}
	records := make([]dnsRecord, 0, recordCount)
	for range recordCount {
		name, next, err := decodeDNSName(packet, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+10 > len(packet) {
			return nil, errors.New("truncated DNS resource record")
		}
		recordType := binary.BigEndian.Uint16(packet[offset : offset+2])
		dataLength := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		dataOffset := offset + 10
		dataEnd := dataOffset + dataLength
		if dataEnd > len(packet) {
			return nil, errors.New("truncated DNS record data")
		}
		record := dnsRecord{name: name, type_: recordType}
		switch recordType {
		case dnsTypeA:
			if dataLength == 4 {
				var address [4]byte
				copy(address[:], packet[dataOffset:dataEnd])
				record.address = netip.AddrFrom4(address)
			}
		case dnsTypePTR:
			record.target, _, _ = decodeDNSName(packet, dataOffset)
		case dnsTypeSRV:
			if dataLength >= 7 {
				record.target, _, _ = decodeDNSName(packet, dataOffset+6)
			}
		}
		records = append(records, record)
		offset = dataEnd
	}
	return records, nil
}

func decodeDNSName(packet []byte, start int) (string, int, error) {
	if start < 0 || start >= len(packet) {
		return "", start, errors.New("DNS name starts outside packet")
	}
	labels := make([]string, 0, 4)
	offset := start
	next := -1
	for steps := 0; steps <= len(packet); steps++ {
		if offset >= len(packet) {
			return "", start, errors.New("truncated DNS name")
		}
		length := int(packet[offset])
		if length == 0 {
			if next < 0 {
				next = offset + 1
			}
			return strings.Join(labels, ".") + ".", next, nil
		}
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return "", start, errors.New("truncated DNS compression pointer")
			}
			pointer := (length&0x3f)<<8 | int(packet[offset+1])
			if pointer >= len(packet) {
				return "", start, errors.New("DNS compression pointer is outside packet")
			}
			if next < 0 {
				next = offset + 2
			}
			offset = pointer
			continue
		}
		if length&0xc0 != 0 || length > 63 || offset+1+length > len(packet) {
			return "", start, errors.New("invalid DNS label")
		}
		labels = append(labels, string(packet[offset+1:offset+1+length]))
		offset += 1 + length
	}
	return "", start, errors.New("DNS compression pointer loop")
}

func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}
