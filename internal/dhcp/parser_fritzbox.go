package dhcp

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FritzBoxParser reads DHCP leases via the FritzBox TR-064 SOAP interface.
type FritzBoxParser struct {
	URL      string // z.B. "http://192.168.178.1:49000"
	User     string
	Password string
	Client   *http.Client // nil = default with 10s timeout
}

func (p *FritzBoxParser) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

const (
	hostsServiceType = "urn:dslforum-org:service:Hosts:1"
	hostsControlURL  = "/upnp/control/hosts"
)

// soapEnvelope builds a SOAP request body.
func soapEnvelope(action, body string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body>` + body + `</s:Body>` +
		`</s:Envelope>`
}

// soapResponse represents the generic SOAP response.
type soapResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Content []byte `xml:",innerxml"`
	} `xml:"Body"`
}

// hostNumberResponse repraesentiert GetHostNumberOfEntries-Antwort.
type hostNumberResponse struct {
	XMLName         xml.Name `xml:"GetHostNumberOfEntriesResponse"`
	NumberOfEntries int      `xml:"NewHostNumberOfEntries"`
}

// hostEntryResponse repraesentiert GetGenericHostEntry-Antwort.
type hostEntryResponse struct {
	XMLName    xml.Name `xml:"GetGenericHostEntryResponse"`
	IPAddress  string   `xml:"NewIPAddress"`
	MACAddress string   `xml:"NewMACAddress"`
	HostName   string   `xml:"NewHostName"`
	Active     int      `xml:"NewActive"`
}

// Parse reads all active hosts from the FritzBox.
func (p *FritzBoxParser) Parse(ctx context.Context) ([]Lease, error) {
	count, err := p.getHostCount(ctx)
	if err != nil {
		return nil, fmt.Errorf("fritzbox: host count: %w", err)
	}

	leases := make([]Lease, 0, count)
	for i := 0; i < count; i++ {
		entry, err := p.getHostEntry(ctx, i)
		if err != nil {
			continue // skip individual faulty entries
		}

		if entry.Active != 1 || entry.HostName == "" || entry.IPAddress == "" {
			continue
		}

		leases = append(leases, Lease{
			MAC:      entry.MACAddress,
			IP:       entry.IPAddress,
			Hostname: entry.HostName,
		})
	}

	return leases, nil
}

func (p *FritzBoxParser) getHostCount(ctx context.Context) (int, error) {
	body := soapEnvelope("GetHostNumberOfEntries",
		`<u:GetHostNumberOfEntries xmlns:u="`+hostsServiceType+`"/>`)

	respBody, err := p.doSOAP(ctx, "GetHostNumberOfEntries", body)
	if err != nil {
		return 0, err
	}

	// Response is nested inside SOAP body
	var env soapResponse
	if err := xml.Unmarshal(respBody, &env); err != nil {
		return 0, fmt.Errorf("fritzbox: XML parse: %w", err)
	}

	var resp hostNumberResponse
	if err := xml.Unmarshal(env.Body.Content, &resp); err != nil {
		return 0, fmt.Errorf("fritzbox: parse host count: %w", err)
	}

	return resp.NumberOfEntries, nil
}

func (p *FritzBoxParser) getHostEntry(ctx context.Context, index int) (*hostEntryResponse, error) {
	body := soapEnvelope("GetGenericHostEntry",
		`<u:GetGenericHostEntry xmlns:u="`+hostsServiceType+`">`+
			`<NewIndex>`+strconv.Itoa(index)+`</NewIndex>`+
			`</u:GetGenericHostEntry>`)

	respBody, err := p.doSOAP(ctx, "GetGenericHostEntry", body)
	if err != nil {
		return nil, err
	}

	var env soapResponse
	if err := xml.Unmarshal(respBody, &env); err != nil {
		return nil, fmt.Errorf("fritzbox: XML parse: %w", err)
	}

	var resp hostEntryResponse
	if err := xml.Unmarshal(env.Body.Content, &resp); err != nil {
		return nil, fmt.Errorf("fritzbox: parse host entry %d: %w", index, err)
	}

	return &resp, nil
}

func (p *FritzBoxParser) doSOAP(ctx context.Context, action, body string) ([]byte, error) {
	url := strings.TrimRight(p.URL, "/") + hostsControlURL

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("fritzbox: create request: %w", err)
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", hostsServiceType+"#"+action)

	if p.User != "" && p.Password != "" {
		req.SetBasicAuth(p.User, p.Password)
	}

	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fritzbox: SOAP %s: %w", action, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fritzbox: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fritzbox: SOAP %s: HTTP %d", action, resp.StatusCode)
	}

	return respBody, nil
}
