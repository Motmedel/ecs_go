package ecs

import (
	"fmt"
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

func ParseHTTPRequest(request *http.Request, extractBody bool) (*Base, error) {
	requestUrl := request.URL
	originalUrl := requestUrl.String()

	host := requestUrl.Host
	// NOTE: Copied from `url.splitHostPort`
	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, _ = host[:colon], host[colon+1:]
	}

	trimmedHost := host

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		trimmedHost = host[1 : len(host)-1]
	}

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

	clientIpAddress, clientPort, err := splitAddress(request.RemoteAddr)
	if err != nil {
		return nil, err
	}

	var userAgent *UserAgent
	if userAgentOriginal := request.UserAgent(); userAgentOriginal != "" {
		userAgent = &UserAgent{Original: userAgentOriginal}
	}

	// TODO: Add Public Suffix List parsing from a global variable.

	return &Base{
		Client: &Client{Ip: clientIpAddress, Port: clientPort},
		Http: &Http{
			Request: &HttpRequest{
				Method:   request.Method,
				Body:     body,
				Referrer: request.Referer(),
			},
			Version: fmt.Sprintf("%d.%d", request.ProtoMajor, request.ProtoMinor),
		},
		Server: server,
		Url: &Url{
			Domain:   host,
			Fragment: requestUrl.Fragment,
			Original: originalUrl,
			Password: password,
			Path:     requestUrl.Path,
			Port:     port,
			Query:    requestUrl.RawQuery,
			Scheme:   requestUrl.Scheme,
			Username: username,
		},
		UserAgent: userAgent,
	}, nil
}
