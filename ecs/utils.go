package ecs

import (
	"fmt"
	"golang.org/x/net/publicsuffix"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func splitAddress(address string) (string, int, error) {
	ip, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return ip, 0, err
	}

	return ip, portNumber, nil
}

// NOTE: Copied
// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func GetDomainBreakdown(domainString string) *DomainBreakdown {
	etld, icann := publicsuffix.PublicSuffix(domainString)
	if !icann && strings.IndexByte(etld, '.') == -1 {
		return nil
	}

	registeredDomain, err := publicsuffix.EffectiveTLDPlusOne(domainString)
	if err != nil {
		return nil
	}

	domainBreakdown := DomainBreakdown{
		TopLevelDomain:   etld,
		RegisteredDomain: registeredDomain,
	}

	if subdomain := strings.TrimSuffix(domainString, "."+registeredDomain); subdomain != domainString {
		domainBreakdown.Subdomain = subdomain
	}

	return &domainBreakdown
}

func ParseHTTPRequest(request *http.Request, extractBody bool) (*Base, error) {
	if request == nil {
		return nil, nil
	}

	requestUrl := request.URL
	originalUrl := requestUrl.String()

	host := requestUrl.Host
	if host == "" {
		host = request.Host
	}
	// NOTE: Copied from `url.splitHostPort`
	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, _ = host[:colon], host[colon+1:]
	}

	trimmedHost := host

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		trimmedHost = host[1 : len(host)-1]
	}

	domainBreakdown := GetDomainBreakdown(trimmedHost)

	var port int
	if portString := requestUrl.Port(); portString != "" {
		port, _ = strconv.Atoi(portString)
	}

	var server *Server
	if trimmedHost != "" || port != 0 {
		server = &Server{Address: trimmedHost, Port: port}
		if ip := net.ParseIP(trimmedHost); ip != nil {
			server.Ip = trimmedHost
		} else {
			server.Domain = trimmedHost
			if domainBreakdown != nil {
				server.RegisteredDomain = domainBreakdown.RegisteredDomain
				server.Subdomain = domainBreakdown.Subdomain
				server.TopLevelDomain = domainBreakdown.TopLevelDomain
			}
		}
	}

	var username string
	var password string
	if userInfo := requestUrl.User; userInfo != nil {
		username = userInfo.Username()
		password, _ = userInfo.Password()
	}

	var body *HttpBody
	if extractBody {
		data, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		body = &HttpBody{
			Bytes:   len(data),
			Content: string(data),
		}
	}

	var client *Client
	if request.RemoteAddr != "" {
		clientIpAddress, clientPort, err := splitAddress(request.RemoteAddr)
		if err != nil {
			return nil, err
		}
		client = &Client{Ip: clientIpAddress, Port: clientPort}
	}

	var userAgent *UserAgent
	if userAgentOriginal := request.UserAgent(); userAgentOriginal != "" {
		userAgent = &UserAgent{Original: userAgentOriginal}
	}

	url := &Url{
		Domain:   host,
		Fragment: requestUrl.Fragment,
		Original: originalUrl,
		Password: password,
		Path:     requestUrl.Path,
		Port:     port,
		Query:    requestUrl.RawQuery,
		Scheme:   requestUrl.Scheme,
		Username: username,
	}
	if domainBreakdown != nil {
		url.RegisteredDomain = domainBreakdown.RegisteredDomain
		url.Subdomain = domainBreakdown.Subdomain
		url.TopLevelDomain = domainBreakdown.TopLevelDomain
	}

	return &Base{
		Client: client,
		Http: &Http{
			Request: &HttpRequest{
				Body:        body,
				ContentType: request.Header.Get("Content-Type"),
				Method:      request.Method,
				Referrer:    request.Referer(),
			},
			Version: fmt.Sprintf("%d.%d", request.ProtoMajor, request.ProtoMinor),
		},
		Server:    server,
		Url:       url,
		UserAgent: userAgent,
	}, nil
}
