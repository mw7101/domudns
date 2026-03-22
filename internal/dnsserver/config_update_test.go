package dnsserver

import (
	"sync"
	"testing"
)

func TestApplyConfig_NoConcurrentRace(t *testing.T) {
	h := &Handler{}
	h.blockMode.Store("nxdomain")
	s := &Server{handler: h}

	var wg sync.WaitGroup

	// 20 goroutines writing via ApplyConfig
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mode := "zero_ip"
			if i%2 == 0 {
				mode = "nxdomain"
			}
			s.ApplyConfig(ConfigUpdate{BlockMode: &mode})
		}(i)
	}

	// 20 goroutines reading blockMode (simulates ServeDNS)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = h.blockMode.Load().(string)
			}
		}()
	}
	wg.Wait()
}
