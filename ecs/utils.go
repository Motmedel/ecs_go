package ecs

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelNet "github.com/Motmedel/utils_go/pkg/net"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	"net"
	"net/http"
	"strconv"
	"strings"
)

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

func ParseHttpRequest(request *http.Request, bodyData []byte) (*Base, error) {
	if request == nil {
		return nil, nil
	}

	network := &Network{Protocol: "http"}

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

	domainBreakdown := domain_breakdown.GetDomainBreakdown(trimmedHost)

	var port int
	if portString := requestUrl.Port(); portString != "" {
		port, _ = strconv.Atoi(portString)
	}

	var server *Target
	if trimmedHost != "" || port != 0 {
		server = &Target{Address: trimmedHost, Port: port}
		if ip := net.ParseIP(trimmedHost); ip != nil {
			server.Ip = trimmedHost
			if ipVersion := motmedelNet.GetIpVersion(&ip); ipVersion == 4 {
				network.Type = "ipv4"
			} else if ipVersion == 6 {
				network.Type = "ipv6"
			}
		} else {
			server.Domain = trimmedHost
			if domainBreakdown != nil {
				server.RegisteredDomain = domainBreakdown.RegisteredDomain
				server.Subdomain = domainBreakdown.Subdomain
				server.TopLevelDomain = domainBreakdown.TopLevelDomain
			}
		}
	}

	if serverTcpAddr, ok := request.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
		if server == nil {
			server = &Target{}
		}
		server.Ip = serverTcpAddr.IP.String()
		server.Port = serverTcpAddr.Port

		network.Transport = "tcp"
		network.IanaNumber = "6"

		if ipVersion := motmedelNet.GetIpVersion(&serverTcpAddr.IP); ipVersion == 4 {
			network.Type = "ipv4"
		} else if ipVersion == 6 {
			network.Type = "ipv6"
		}
	}

	var username string
	var password string
	if userInfo := requestUrl.User; userInfo != nil {
		username = userInfo.Username()
		password, _ = userInfo.Password()
	}

	var body *HttpBody
	if len(bodyData) != 0 {
		body = &HttpBody{Bytes: len(bodyData), Content: string(bodyData)}
	}

	var client *Target
	if remoteAddr := request.RemoteAddr; remoteAddr != "" {
		clientIpAddress, clientPort, err := motmedelNet.SplitAddress(remoteAddr)
		if err != nil {
			return nil, &motmedelErrors.InputError{
				Message: "An error occurred when splitting a remote address.",
				Cause:   err,
				Input:   remoteAddr,
			}
		}
		client = &Target{Ip: clientIpAddress, Port: clientPort}
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
		Network:   network,
	}, nil
}
