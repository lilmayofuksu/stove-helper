package helper

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/StoveGI/stove-helper/pkg/ec2b"
	"github.com/StoveGI/stove-helper/pkg/net"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/rs/zerolog/log"
)

func (s *Service) initSniffer() error {
	s.keyStore = &KeyStore{keyMap: make(map[uint16][]byte)}
	s.cmdIdMap = make(map[uint16]string)
	s.protoMap = make(map[string]*desc.MessageDescriptor)

	p, err := os.ReadFile(s.config.DataConfig.CmdIDPath)
	if err != nil {
		return err
	}
	parser := protoparse.Parser{ImportPaths: []string{s.config.DataConfig.ProtoPath}}
	if err := s.parseProto(parser, "QueryCurrRegionHttpRsp"); err != nil {
		return err
	}
	if err := s.parseProto(parser, "PacketHead"); err != nil {
		return err
	}
	for _, line := range strings.Split(string(p), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ",")
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "DebugNotify" {
			continue
		}
		v, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to parse cmdid %s", parts[1])
			continue
		}
		s.cmdIdMap[uint16(v)] = parts[0]
		dsec, err := parser.ParseFiles(parts[0] + ".proto")
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to parse proto %s", parts[0])
			continue
		}
		s.protoMap[parts[0]] = dsec[0].FindMessage(parts[0])
	}
	log.Info().Int("#packets", len(s.cmdIdMap)).Int("#fields", len(s.protoMap)).Msg("Successfully loaded proto files")
	rest, _ := os.ReadFile(s.config.DataConfig.PrivateKeyPath)
	var ok bool
	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		if block.Type == "RSA PRIVATE KEY" {
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			} else if s.priv, ok = k.(*rsa.PrivateKey); !ok {
				return fmt.Errorf("failed to parse private key")
			}
			break
		}
		if len(rest) == 0 {
			if s.priv == nil {
				return fmt.Errorf("failed to parse private key")
			}
			break
		}
	}
	s.initSecret(s.config.DataConfig.DispatchRegion)
	s.handle, err = pcap.OpenLive(s.config.Device, 1500, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	if err := s.handle.SetBPFFilter("udp portrange 22101-22102"); err != nil {
		return err
	}
	log.Info().Str("device", s.config.Device).Msg("Successfully opened device")
	return nil
}

func (s *Service) parseProto(parser protoparse.Parser, name string) error {
	dsec, err := parser.ParseFiles(name + ".proto")
	if err != nil {
		return err
	}
	s.protoMap[name] = dsec[0].FindMessage(name)
	return nil
}

func decrypt(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	out := make([]byte, 0, 1024)
	for len(ciphertext) > 0 {
		chunkSize := 256
		if chunkSize > len(ciphertext) {
			chunkSize = len(ciphertext)
		}
		chunk := ciphertext[:chunkSize]
		ciphertext = ciphertext[chunkSize:]
		b, err := rsa.DecryptPKCS1v15(rand.Reader, priv, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

func (s *Service) initSecret(url string) {
	log.Info().Str("url", url).Msg("Initializing secret")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to create http request")
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to send http request")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Error().Int("status", resp.StatusCode).Str("url", url).Msg("Failed to send http request")
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to read http response")
		return
	}
	var v map[string]string
	if err := json.Unmarshal(body, &v); err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to unmarshal http response")
		return
	}
	content, err := base64.StdEncoding.DecodeString(v["content"])
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to decode http response")
		return
	}
	body, err = decrypt(s.priv, content)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to decrypt http response")
		return
	}
	pb := dynamic.NewMessage(s.protoMap["QueryCurrRegionHttpRsp"])
	if err := pb.Unmarshal(body); err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to unmarshal http response")
		return
	}
	ec2b, err := ec2b.Load(pb.GetFieldByName("client_secret_key").([]byte))
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to load ec2b")
		return
	}
	key := ec2b.Key()
	log.Info().Uint16("magic", binary.BigEndian.Uint16(key)^0x4567).Msg("Successfully initialized secret")
	s.keyStore.keyMap[binary.BigEndian.Uint16(key)^0x4567] = key
}

func (s *Service) runSniffer() {
	pcapng, err := os.Create(path.Join(s.config.DataConfig.OutputPath, time.Now().Format("2006-01-02 15-04-05")+".pcapng"))
	if err != nil {
		log.Error().Err(err).Msg("Failed to create pcapng file")
		return
	}
	defer pcapng.Close()
	s.rawlog, err = os.Create(path.Join(s.config.DataConfig.OutputPath, time.Now().Format("2006-01-02 15-04-05")+".rawlog.yaml"))
	if err != nil {
		log.Error().Err(err).Msg("Failed to create rawlog file")
		return
	}
	defer s.rawlog.Close()
	pcapngWriter, err := pcapgo.NewNgWriter(pcapng, s.handle.LinkType())
	if err != nil {
		log.Error().Err(err).Msg("Failed to create pcapng writer")
		return
	}
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for packet := range packetSource.Packets() {
		err := pcapngWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			log.Error().Err(err).Msg("Failed to write packet to pcapng")
			return
		}
		p := packet.ApplicationLayer().Payload()
		if len(p) < net.IKCP_OVERHEAD {
			continue
		}
		udp := packet.TransportLayer().(*layers.UDP)
		s.handlePayload(p, udp.SrcPort == 22101 || udp.SrcPort == 22102, packet.Metadata().Timestamp)
	}
}

func (s *Service) handlePayload(p []byte, flag bool, t time.Time) {
	conv := binary.LittleEndian.Uint64(p)
	var kcp *net.KCP
	if flag {
		if s.incoming == nil {
			s.incoming = net.NewKCP(conv, func(buf []byte, size int) {})
			s.incoming.SetMtu(1200)
			s.incoming.NoDelay(1, 20, 2, 1)
			s.incoming.WndSize(255, 255)
		}
		kcp = s.incoming
	} else {
		if s.outgoing == nil {
			s.outgoing = net.NewKCP(conv, func(buf []byte, size int) {})
			s.outgoing.SetMtu(1200)
			s.outgoing.NoDelay(1, 20, 2, 1)
			s.outgoing.WndSize(255, 255)
		}
		kcp = s.outgoing
	}
	_ = kcp.Input(p, true, true)
	size := kcp.PeekSize()
	for size > 0 {
		packet := &Packet{}
		packet.flag = flag
		packet.data = make([]byte, size)
		packet.time = t
		_ = kcp.Recv(packet.data)
		go s.handlePacket(packet)
		size = kcp.PeekSize()
	}
	kcp.Update()
}
