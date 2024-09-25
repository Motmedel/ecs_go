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

func ParseHttp(
	request *http.Request,
	requestBodyData []byte,
	response *http.Response,
	responseBodyData []byte,
) (*Base, error) {
	if request == nil && len(requestBodyData) == 0 && response == nil && len(responseBodyData) == 0 {
		return nil, nil
	}

	network := &Network{Protocol: "http"}

	var client *Target
	var httpVersion string
	var server *Target
	var url *Url
	var userAgent *UserAgent

	var httpRequest *HttpRequest
	if request != nil {
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

		var requestBody *HttpBody
		var requestBodyMimeType string
		if len(requestBodyData) != 0 {
			requestBody = &HttpBody{Bytes: len(requestBodyData), Content: string(requestBodyData)}
			requestBodyMimeType = http.DetectContentType(requestBodyData)
		}

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

		if userAgentOriginal := request.UserAgent(); userAgentOriginal != "" {
			userAgent = &UserAgent{Original: userAgentOriginal}
		}

		url = &Url{
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

		httpRequest = &HttpRequest{
			Body:        requestBody,
			ContentType: request.Header.Get("Content-Type"),
			Method:      request.Method,
			Referrer:    request.Referer(),
			MimeType:    requestBodyMimeType,
		}

		httpVersion = fmt.Sprintf("%d.%d", request.ProtoMajor, request.ProtoMinor)
	}

	var httpResponse *HttpResponse
	if response != nil {
		var responseBody *HttpBody
		var responseBodyMimeType string
		if len(responseBodyData) != 0 {
			responseBody = &HttpBody{Bytes: len(responseBodyData), Content: string(responseBodyData)}
			responseBodyMimeType = http.DetectContentType(responseBodyData)
		}
		httpResponse = &HttpResponse{
			Body:        responseBody,
			StatusCode:  response.StatusCode,
			ContentType: response.Header.Get("Content-Type"),
			MimeType:    responseBodyMimeType,
		}
	}

	var ecsHttp *Http
	if httpRequest != nil || httpResponse != nil {
		ecsHttp = &Http{
			Request:  httpRequest,
			Response: httpResponse,
			Version:  httpVersion,
		}
	}

	return &Base{
		Client:    client,
		Http:      ecsHttp,
		Server:    server,
		Url:       url,
		UserAgent: userAgent,
		Network:   network,
	}, nil
}
