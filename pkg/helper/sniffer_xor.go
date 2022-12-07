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

func bruteforce(ms, seed uint64, p []byte) (uint64, []byte) {
	r1 := csharp.NewRand()
	r2 := mt19937.NewRand()
	v := binary.BigEndian.Uint64(p)
	for i := uint64(0); i < 1000; i++ {
		r1.Seed(int64(ms + i))
		for j := uint64(0); j < 1000; j++ {
			s := r1.Uint64()
			r2.Seed(int64(s ^ seed))
			r2.Seed(int64(r2.Uint64()))
			r2.Uint64()
			if (v^r2.Uint64())&0xFFFF0000FF00FFFF == 0x4567000000000000 {
				log.Info().Uint64("#seed", ms+i).Uint64("depth", j).Msg("Found seed")
				return ms + i, mt19937.NewKeyBlock(s ^ seed).Key()
			}
			if i != 0 && (i > 100 || i+j > 100) {
				break
			}
		}
		r1.Seed(int64(ms - i - 1))
		for j := uint64(0); j < 1000; j++ {
			s := r1.Uint64()
			r2.Seed(int64(s ^ seed))
			r2.Seed(int64(r2.Uint64()))
			r2.Uint64()
			if (v^r2.Uint64())&0xFFFF0000FF00FFFF == 0x4567000000000000 {
				log.Info().Uint64("#seed", ms-i-1).Uint64("depth", j).Msg("Found seed")
				return ms - i - 1, mt19937.NewKeyBlock(s ^ seed).Key()
			}
			if i+1 > 100 || i+j+1 > 100 {
				break
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
