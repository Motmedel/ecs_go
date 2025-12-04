package ecs

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	motmedelNet "github.com/Motmedel/utils_go/pkg/net"
	motmedelNetCommunityId "github.com/Motmedel/utils_go/pkg/net/community_id"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	motmedelTlsTypes "github.com/Motmedel/utils_go/pkg/tls/types"
	motmedelWhoisTypes "github.com/Motmedel/utils_go/pkg/whois/types"
)

const (
	timestampFormat = "2006-01-02T15:04:05.999999999Z"
)

// NOTE: Copied
// validOptionalPort reports whether port is either an empty string or matches /^:\d*$/
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

const unknownPlaceholder = "(unknown)"

func MakeConnectionMessage(base *Base, suffix string) string {
	if base == nil {
		return ""
	}

	var sourceIpAddress string
	var destinationIpAddress string
	var sourcePort int
	var destinationPort int

	if ecsSource := base.Source; ecsSource != nil {
		sourceIpAddress = ecsSource.Ip
		sourcePort = ecsSource.Port
	}

	if ecsDestination := base.Destination; ecsDestination != nil {
		destinationIpAddress = ecsDestination.Ip
		destinationPort = ecsDestination.Port
	}

	sourcePart := unknownPlaceholder
	if sourceIpAddress != "" && sourcePort != 0 {
		sourcePart = net.JoinHostPort(sourceIpAddress, strconv.Itoa(sourcePort))
	} else if sourceIpAddress != "" {
		sourcePart = sourceIpAddress
	} else if sourcePort != 0 {
		sourcePart = fmt.Sprintf(":%d", sourcePort)
	}

	destinationPart := unknownPlaceholder
	if destinationIpAddress != "" && destinationPort != 0 {
		destinationPart = net.JoinHostPort(destinationIpAddress, strconv.Itoa(destinationPort))
	} else if destinationIpAddress != "" {
		destinationPart = destinationIpAddress
	} else if destinationPort != 0 {
		destinationPart = fmt.Sprintf(":%d", destinationPort)
	}

	transportPart := unknownPlaceholder
	if ecsNetwork := base.Network; ecsNetwork != nil {
		if ecsNetwork.Transport != "" {
			transportPart = ecsNetwork.Transport
		} else if ecsNetwork.IanaNumber != "" {
			transportPart = fmt.Sprintf("(%s)", ecsNetwork.IanaNumber)
		}
	}

	var message string

	if sourcePart == unknownPlaceholder && destinationPart == unknownPlaceholder && transportPart == unknownPlaceholder {
		message = unknownPlaceholder
		if suffix != "" {
			message = suffix
		}
	} else {
		message = fmt.Sprintf("%s to %s %s", sourcePart, destinationPart, transportPart)
		if suffix != "" {
			message += fmt.Sprintf(" - %s", suffix)
		}
	}

	return message
}

func DefaultHeaderExtractorWithMasking(requestResponse any, maskNames []string, maskValue string) string {
	var header http.Header

	switch typedRequestResponse := requestResponse.(type) {
	case *http.Request:
		header = typedRequestResponse.Header
	case *http.Response:
		header = typedRequestResponse.Header
	default:
		return ""
	}

	var headerStrings []string

	for name, values := range header {
		shouldMask := slices.Contains(maskNames, strings.ToLower(name))
		for _, value := range values {
			if shouldMask {
				value = maskValue
			}
			headerStrings = append(headerStrings, fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}

	return strings.Join(headerStrings, "")
}

func DefaultMaskedHeaderExtractor(requestResponse any) string {
	return DefaultHeaderExtractorWithMasking(
		requestResponse,
		[]string{"authorization", "cookie", "set-cookie"},
		"(MASKED)",
	)
}

func DefaultHeaderExtractor(requestResponse any) string {
	return DefaultHeaderExtractorWithMasking(requestResponse, nil, "")
}

func ParseHttp(
	request *http.Request,
	requestBodyData []byte,
	response *http.Response,
	responseBodyData []byte,
	headerExtractor func(any) string,
) (*Base, error) {
	if request == nil && len(requestBodyData) == 0 && response == nil && len(responseBodyData) == 0 {
		return nil, nil
	}

	network := &Network{Protocol: "http"}

	var client *Target
	var httpVersion string
	var server *Target
	var ecsUrl *Url
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
				return nil, motmedelErrors.New(
					fmt.Errorf("split address: %w", err),
					remoteAddr,
				)
			}
			client = &Target{Ip: clientIpAddress, Port: clientPort}
		}

		if userAgentOriginal := request.UserAgent(); userAgentOriginal != "" {
			userAgent = &UserAgent{Original: userAgentOriginal}
		}

		ecsUrl = &Url{
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
			ecsUrl.RegisteredDomain = domainBreakdown.RegisteredDomain
			ecsUrl.Subdomain = domainBreakdown.Subdomain
			ecsUrl.TopLevelDomain = domainBreakdown.TopLevelDomain
		}

		httpRequest = &HttpRequest{
			ContentType: request.Header.Get("Content-Type"),
			Method:      request.Method,
			Referrer:    request.Referer(),
		}

		httpVersionMajor := request.ProtoMajor
		httpVersionMinor := request.ProtoMinor

		if httpVersionMajor != 0 || httpVersionMinor != 0 {
			httpVersion = fmt.Sprintf("%d.%d", request.ProtoMajor, request.ProtoMinor)

			if strings.HasPrefix(httpVersion, "3.") {
				network.Transport = "udp"
				network.IanaNumber = "17"
			} else {
				network.Transport = "tcp"
				network.IanaNumber = "6"
			}

			if server != nil && client != nil {
				serverIp := net.ParseIP(server.Ip)
				clientIp := net.ParseIP(client.Ip)
				serverPort := server.Port
				clientPort := client.Port

				protocolNumber, _ := strconv.Atoi(network.IanaNumber)

				if serverIp != nil && clientIp != nil && serverPort != 0 && clientPort != 0 && protocolNumber != 0 {
					communityId := motmedelNetCommunityId.MakeFlowTupleHash(
						serverIp,
						clientIp,
						uint16(serverPort),
						uint16(clientPort),
						uint8(protocolNumber),
					)

					if communityId != "" {
						network.CommunityId = append(network.CommunityId, communityId)
					}
				}
			}
		}
	}

	if headerExtractor != nil {
		if normalizedHeader := headerExtractor(request); normalizedHeader != "" {
			httpRequest.HttpHeaders = &HttpHeaders{Normalized: normalizedHeader}
		}
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

		if headerExtractor != nil {
			if normalizedHeader := headerExtractor(response); normalizedHeader != "" {
				httpResponse.HttpHeaders = &HttpHeaders{Normalized: normalizedHeader}
			}
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

	if client == nil && ecsHttp == nil && server == nil && ecsUrl == nil && userAgent == nil && network == nil {
		return nil, nil
	}

	return &Base{
		Client:    client,
		Http:      ecsHttp,
		Server:    server,
		Url:       ecsUrl,
		UserAgent: userAgent,
		Network:   network,
	}, nil
}

func ParseHttpContext(
	httpContext *motmedelHttpTypes.HttpContext,
	// TODO: Rework this. `any` is not nice. Use an interface?
	headerExtractor func(requestResponse any) string,
) (*Base, error) {
	if httpContext == nil {
		return nil, nil
	}

	var user *User
	if httpContextUser := httpContext.User; httpContextUser != nil {
		user = &User{
			Domain:   httpContextUser.Domain,
			Email:    httpContextUser.Email,
			FullName: httpContextUser.FullName,
			Hash:     httpContextUser.Hash,
			Id:       httpContextUser.Id,
			Name:     httpContextUser.Name,
			Roles:    httpContextUser.Roles,
		}

		var group *Group
		if httpContextUserGroup := httpContextUser.Group; httpContextUserGroup != nil {
			group = &Group{
				Domain: httpContextUserGroup.Domain,
				Id:     httpContextUserGroup.Id,
				Name:   httpContextUserGroup.Name,
			}
		}
		user.Group = group
	}

	base, err := ParseHttp(
		httpContext.Request,
		httpContext.RequestBody,
		httpContext.Response,
		httpContext.ResponseBody,
		headerExtractor,
	)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("parse http: %w", err),
		)
	}

	if base != nil {
		base.User = user
	}

	return base, nil
}

func parseTarget(rawAddress string, rawIpAddress string, rawPort int) (*Target, error) {
	var target *Target

	if rawIpAddress != "" {
		ipAddressUrl := fmt.Sprintf("fake://%s", rawIpAddress)
		urlParsedClientIpAddress, err := url.Parse(ipAddressUrl)
		if err != nil {
			return nil, motmedelErrors.NewWithTrace(
				fmt.Errorf("url parse (crafted ip address url): %w", err),
				ipAddressUrl,
			)
		}

		port := rawPort

		if portString := urlParsedClientIpAddress.Port(); portString != "" {
			port, err = strconv.Atoi(portString)
			if err != nil {
				return nil, motmedelErrors.NewWithTrace(
					fmt.Errorf("strconv atoi (port string): %w", err),
					portString,
				)
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

	clientAddress := whoisContext.ClientAddress
	clientIpAddress := whoisContext.ClientIpAddress
	clientPort := whoisContext.ClientPort
	client, err := parseTarget(clientAddress, clientIpAddress, clientPort)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("parse target (client data): %w", err),
			clientAddress, clientAddress, clientPort,
		)
	}
	var requestBody *Body
	if requestData := whoisContext.RequestData; len(requestData) > 0 {
		requestBody = &Body{Bytes: len(requestData), Content: string(requestData)}
	}

	serverAddress := whoisContext.ServerAddress
	serverIpAddress := whoisContext.ServerIpAddress
	serverPort := whoisContext.ServerPort
	server, err := parseTarget(serverAddress, serverIpAddress, serverPort)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("parse target (server data): %w", err),
			serverAddress, serverIpAddress, serverPort,
		)
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

func CommunityIdFromTargets(sourceTarget *Target, destinationTarget *Target, protocolNumber int) string {
	if sourceTarget == nil {
		return ""
	}

	if destinationTarget == nil {
		return ""
	}

	if protocolNumber == 0 {
		return ""
	}

	sourceTargetIp := net.ParseIP(sourceTarget.Ip)
	destinationTargetIp := net.ParseIP(destinationTarget.Ip)
	sourceTargetPort := sourceTarget.Port
	destinationTargetPort := destinationTarget.Port

	if sourceTargetIp == nil || destinationTargetIp == nil || sourceTargetPort == 0 || destinationTargetPort == 0 {
		return ""
	}

	return motmedelNetCommunityId.MakeFlowTupleHash(
		sourceTargetIp,
		destinationTargetIp,
		uint16(sourceTargetPort),
		uint16(destinationTargetPort),
		uint8(protocolNumber),
	)
}

func EnrichWithTlsConnectionState(base *Base, connectionState *tls.ConnectionState, clientInitiated bool) {
	if base == nil {
		return
	}

	if connectionState == nil {
		return
	}

	ecsTls := base.Tls
	if ecsTls == nil {
		ecsTls = &Tls{}
		base.Tls = ecsTls
	}

	ecsTls.Cipher = tls.CipherSuiteName(connectionState.CipherSuite)
	ecsTls.Established = connectionState.HandshakeComplete
	ecsTls.NextProtocol = strings.ToLower(connectionState.NegotiatedProtocol)
	ecsTls.Resumed = connectionState.DidResume

	switch connectionState.Version {
	case tls.VersionSSL30:
		ecsTls.TlsProtocol = &TlsProtocol{Name: "ssl", Version: "3"}
	case tls.VersionTLS10:
		ecsTls.TlsProtocol = &TlsProtocol{Name: "tls", Version: "1.0"}
	case tls.VersionTLS11:
		ecsTls.TlsProtocol = &TlsProtocol{Name: "tls", Version: "1.1"}
	case tls.VersionTLS12:
		ecsTls.TlsProtocol = &TlsProtocol{Name: "tls", Version: "1.2"}
	case tls.VersionTLS13:
		ecsTls.TlsProtocol = &TlsProtocol{Name: "tls", Version: "1.3"}
	}

	if serverName := connectionState.ServerName; serverName != "" {
		ecsTlsClient := ecsTls.Client
		if ecsTlsClient == nil {
			ecsTlsClient = &TlsClient{}
			ecsTls.Client = ecsTlsClient
		}

		ecsTlsClient.ServerName = serverName
	}

	if peerCertificates := connectionState.PeerCertificates; len(peerCertificates) > 0 {
		if leaf := peerCertificates[0]; leaf != nil {
			// TODO: Add more fields.

			issuer := leaf.Issuer.String()
			subject := leaf.Subject.String()
			notAfter := leaf.NotAfter.UTC().Format(timestampFormat)
			notBefore := leaf.NotBefore.UTC().Format(timestampFormat)

			if !clientInitiated {
				ecsTlsClient := ecsTls.Client
				if ecsTlsClient == nil {
					ecsTlsClient = &TlsClient{}
					ecsTls.Client = ecsTlsClient
				}

				ecsTlsClient.Issuer = issuer
				ecsTlsClient.Subject = subject
				ecsTlsClient.NotAfter = notAfter
				ecsTlsClient.NotBefore = notBefore
			} else {
				ecsTlsServer := ecsTls.Server
				if ecsTlsServer == nil {
					ecsTlsServer = &TlsServer{}
					ecsTls.Server = ecsTlsServer
				}

				ecsTlsServer.Issuer = issuer
				ecsTlsServer.Subject = subject
				ecsTlsServer.NotAfter = notAfter
				ecsTlsServer.NotBefore = notBefore
			}
		}
	}
}

func EnrichWithTlsContext(base *Base, tlsContext *motmedelTlsTypes.TlsContext) {
	if base == nil {
		return
	}

	if tlsContext == nil {
		return
	}

	connectionState := tlsContext.ConnectionState
	if connectionState == nil {
		return
	}

	EnrichWithTlsConnectionState(base, connectionState, tlsContext.ClientInitiated)
}
