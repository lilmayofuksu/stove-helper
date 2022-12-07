package helper

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/StoveGI/stove-helper/pkg/rand/csharp"
	"github.com/StoveGI/stove-helper/pkg/rand/mt19937"
)

type KeyStore struct {
	sync.Mutex
	keyMap map[uint16][]byte
}

func (s *Service) xor(p []byte) {
	s.keyStore.Lock()
	key := s.keyStore.keyMap[binary.BigEndian.Uint16(p)]
	if key == nil {
		seed := s.config.Seed
		if seed == 0 {
			seed = s.sentMs
		}
		seed, key = bruteforce(seed, s.serverSeed, p)
		if key == nil {
			s.keyStore.Unlock()
			return
		}
		if s.config.Seed == 0 {
			s.config.Seed = seed
		}
		fmt.Fprintf(s.rawlog, "- seed: %d", seed)
		s.keyStore.keyMap[binary.BigEndian.Uint16(p)] = key
	}
	s.keyStore.Unlock()
	if key != nil {
		xor(p, key)
	}
}

func bruteforce(ms uint64, seed uint64, p []byte) (uint64, []byte) {
	r := csharp.NewRand()
	v := make([]byte, 2)
	for i := ms; i > ms-1000; i-- {
		r.Seed(int64(i))
		for j := uint64(0); j < 1000; j++ {
			s := r.Uint64()
			k := mt19937.NewKeyBlock(s ^ seed)
			copy(v, p)
			k.Xor(v)
			if v[0] == 0x45 && v[1] == 0x67 {
				log.Info().Uint64("#seed", i).Uint64("depth", j).Msg("Found seed")
				return i, k.Key()
			}
		}
	}
	return 0, nil
}

func xor(p, key []byte) {
	for i := 0; i < len(p); i++ {
		p[i] ^= key[i%4096]
	}
}
