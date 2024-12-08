package ecs

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelNet "github.com/Motmedel/utils_go/pkg/net"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	motmedelWhoisTypes "github.com/Motmedel/utils_go/pkg/whois/types"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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

		// TODO: Maybe I can use `parseTarget()`?
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
			ContentType: request.Header.Get("Content-Type"),
			Method:      request.Method,
			Referrer:    request.Referer(),
		}

		httpVersion = fmt.Sprintf("%d.%d", request.ProtoMajor, request.ProtoMinor)
	}

	if len(requestBodyData) != 0 {
		if httpRequest == nil {
			httpRequest = &HttpRequest{}
		}
		httpRequest.Body = &Body{Bytes: len(requestBodyData), Content: string(requestBodyData)}
		httpRequest.MimeType = http.DetectContentType(requestBodyData)
	}

	var httpResponse *HttpResponse
	if response != nil {
		httpResponse = &HttpResponse{
			StatusCode:  response.StatusCode,
			ContentType: response.Header.Get("Content-Type"),
		}
	}

	if len(responseBodyData) != 0 {
		if httpResponse == nil {
			httpResponse = &HttpResponse{}
		}
		httpResponse.Body = &Body{Bytes: len(responseBodyData), Content: string(responseBodyData)}
		httpResponse.MimeType = http.DetectContentType(responseBodyData)
	}

	var ecsHttp *Http
	if httpRequest != nil || httpResponse != nil {
		ecsHttp = &Http{Request: httpRequest, Response: httpResponse, Version: httpVersion}
	}

	if client == nil && ecsHttp == nil && server == nil && url == nil && userAgent == nil && network == nil {
		return nil, nil
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

func ParseHttpContext(httpContext *motmedelHttpTypes.HttpContext) (*Base, error) {
	if httpContext == nil {
		return nil, nil
	}

	return ParseHttp(httpContext.Request, httpContext.RequestBody, httpContext.Response, httpContext.ResponseBody)
}

func parseTarget(rawAddress string, rawIpAddress string, rawPort int) (*Target, error) {
	var target *Target

	if rawIpAddress != "" {
		ipAddressUrl := fmt.Sprintf("fake://%s", rawIpAddress)
		urlParsedClientIpAddress, err := url.Parse(ipAddressUrl)
		if err != nil {
			return nil, &motmedelErrors.InputError{
				Message: "An error occurred when parsing the target IP address as an URL",
				Cause:   err,
				Input:   ipAddressUrl,
			}
		}

		port := rawPort

		if portString := urlParsedClientIpAddress.Port(); portString != "" {
			port, err = strconv.Atoi(portString)
			if err != nil {
				return nil, &motmedelErrors.InputError{
					Message: "An error occurred when parsing the target IP address URL port as an integer.",
					Cause:   err,
					Input:   portString,
				}
			}
		}

		ipAddress := urlParsedClientIpAddress.Hostname()
		address := rawAddress
		if address != "" {
			address = ipAddress
		}

		target = &Target{Address: address, Domain: rawAddress, Ip: ipAddress, Port: port}
	} else if rawAddress != "" {
		target = &Target{
			Address: rawAddress,
			Domain:  rawAddress,
			Port:    rawPort,
		}
	}

	if target != nil {
		if domain := target.Domain; domain != "" {
			domainBreakdown := domain_breakdown.GetDomainBreakdown(domain)
			if domainBreakdown != nil {
				target.RegisteredDomain = domainBreakdown.RegisteredDomain
				target.Subdomain = domainBreakdown.Subdomain
				target.TopLevelDomain = domainBreakdown.TopLevelDomain
			}
		}
	}

	return target, nil
}

func ParseWhoisContext(whoisContext *motmedelWhoisTypes.WhoisContext) (*Base, error) {
	if whoisContext == nil {
		return nil, nil
	}

	client, err := parseTarget(whoisContext.ClientAddress, whoisContext.ClientIpAddress, whoisContext.ClientPort)
	if err != nil {
		return nil, &motmedelErrors.CauseError{
			Message: "An error occurred when parsing client information.",
			Cause:   err,
		}
	}
	var requestBody *Body
	if requestData := whoisContext.RequestData; len(requestData) > 0 {
		requestBody = &Body{Bytes: len(requestData), Content: string(requestData)}
	}

	server, err := parseTarget(whoisContext.ServerAddress, whoisContext.ServerIpAddress, whoisContext.ServerPort)
	if err != nil {
		return nil, &motmedelErrors.CauseError{
			Message: "An error occurred when parsing client information.",
			Cause:   err,
		}
	}
	var responseBody *Body
	if responseData := whoisContext.ResponseData; len(responseData) > 0 {
		responseBody = &Body{Bytes: len(responseData), Content: string(responseData)}
	}

	var whois *Whois
	if requestBody != nil || responseBody != nil {
		whois = &Whois{}
		if requestBody != nil {
			whois.Request = &WhoisRequest{Body: requestBody}
		}
		if responseBody != nil {
			whois.Response = &WhoisResponse{Body: responseBody}
		}
	}

	return &Base{
		Client:  client,
		Network: &Network{Protocol: "whois", Transport: whoisContext.Transport},
		Server:  server,
		Whois:   whois,
	}, nil
}

func EventCreatedReplaceAttr(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return attr
	}

	switch attr.Key {
	case slog.TimeKey:
		return slog.Group("event", slog.Any("created", attr.Value))
	case slog.LevelKey:
		if value, ok := attr.Value.Any().(string); ok {
			return slog.Group("log", slog.String("level", strings.ToLower(value)))
		}
	case slog.MessageKey:
		attr.Key = "message"
	}

	return attr
}

func TimestampReplaceAttr(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return attr
	}

	switch attr.Key {
	case slog.TimeKey:
		attr.Key = "@timestamp"
	case slog.LevelKey:
		if value, ok := attr.Value.Any().(string); ok {
			return slog.Group("log", slog.String("level", strings.ToLower(value)))
		}
	case slog.MessageKey:
		attr.Key = "message"
	}

	return attr
}
