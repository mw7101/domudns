// internal/dnsserver/cache_concurrent_test.go
package dnsserver

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCacheManager_ConcurrentGetSetClean(t *testing.T) {
	cm := NewCacheManager(100, 30*time.Second, 10*time.Second)

	// Seed with entries — use TTL=5s in the A record so Set() does not drop them.
	for i := 0; i < 50; i++ {
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("host%d.example.com.", i), dns.TypeA)
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   fmt.Sprintf("host%d.example.com.", i),
				Ttl:    5,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
		})
		cm.Set(fmt.Sprintf("host%d.example.com.", i), dns.TypeA, msg)
	}

	var wg sync.WaitGroup

	// 10 concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				cm.Get(fmt.Sprintf("host%d.example.com.", id%50), dns.TypeA)
			}
		}(i)
	}

	// 2 concurrent writers
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				req := new(dns.Msg)
				req.SetQuestion(fmt.Sprintf("newhost%d.example.com.", id*50+j), dns.TypeA)
				msg := new(dns.Msg)
				msg.SetReply(req)
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   fmt.Sprintf("newhost%d.example.com.", id*50+j),
						Ttl:    5,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
				})
				cm.Set(fmt.Sprintf("newhost%d.example.com.", id*50+j), dns.TypeA, msg)
			}
		}(i)
	}

	// 1 concurrent cleaner
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			cm.Clean()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg.Wait()
}
