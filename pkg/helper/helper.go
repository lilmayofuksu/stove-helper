package helper

import (
	"crypto/rsa"
	"net/http"
	"os"

	"github.com/google/gopacket/pcap"
	"github.com/jhump/protoreflect/desc"

	"github.com/StoveGI/stove-helper/pkg/config"
	"github.com/StoveGI/stove-helper/pkg/net"
)

type Service struct {
	config *config.Config

	rawlog *os.File
	handle *pcap.Handle

	priv     *rsa.PrivateKey
	keyStore *KeyStore
	cmdIdMap map[uint16]string
	protoMap map[string]*desc.MessageDescriptor

	sentMs     uint64
	serverSeed uint64
	incoming   *net.KCP
	outgoing   *net.KCP
}

func NewService(c config.Config) (*Service, error) {
	s := &Service{config: &c}
	if err := s.initSniffer(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Start() error {
	go s.runSniffer()
	return s.start()
}

func (s *Service) start() error {
	return http.ListenAndServe(":8080", nil)
}
