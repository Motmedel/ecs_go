package ecs

import "github.com/Motmedel/utils_go/pkg/net"

type HttpHeaders struct {
	Normalized string `json:"normalized,omitempty"`
	Original   string `json:"original,omitempty"`
}

type Body struct {
	Bytes   int    `json:"bytes,omitempty"`
	Content string `json:"content,omitempty"`
}

type Target struct {
	net.DomainBreakdown
	Address string            `json:"address,omitempty"`
	Bytes   int               `json:"bytes,omitempty"`
	Domain  string            `json:"domain,omitempty"`
	Ip      string            `json:"ip,omitempty"`
	Mac     string            `json:"mac,omitempty"`
	Nat     *Nat              `json:"nat,omitempty"`
	Packets int               `json:"packets,omitempty"`
	Port    int               `json:"port,omitempty"`
	As      *AutonomousSystem `json:"as,omitempty"`
	Geo     *Geo              `json:"geo,omitempty"`
	User    *User             `json:"user,omitempty"`
}

type Base struct {
	Timestamp string            `json:"@timestamp,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Message   string            `json:"message,omitempty"`
	Tags      string            `json:"tags,omitempty"`

	Client        *Target        `json:"client,omitempty"`
	Cloud         *Cloud         `json:"cloud,omitempty"`
	Destination   *Target        `json:"destination,omitempty"`
	Dns           *Dns           `json:"dns,omitempty"`
	Error         *Error         `json:"error,omitempty"`
	Event         *Event         `json:"event,omitempty"`
	Group         *Group         `json:"group,omitempty"`
	Host          *Host          `json:"host,omitempty"`
	Http          *Http          `json:"http,omitempty"`
	Log           *Log           `json:"log,omitempty"`
	Observer      *Observer      `json:"observer,omitempty"`
	Process       *Process       `json:"process,omitempty"`
	Registry      *Registry      `json:"process,omitempty"`
	Related       *Related       `json:"related,omitempty"`
	Rule          *Rule          `json:"rule,omitempty"`
	Server        *Target        `json:"server,omitempty"`
	Source        *Target        `json:"source,omitempty"`
	Network       *Network       `json:"network,omitempty"`
	Url           *Url           `json:"url,omitempty"`
	User          *User          `json:"user,omitempty"`
	UserAgent     *UserAgent     `json:"user_agent,omitempty"`
	Vulnerability *Vulnerability `json:"vulnerability,omitempty"`

	// NOTE: Custom namespaces
	Whois *Whois `json:"whois,omitempty"`
	Tcp   *Tcp   `json:"tcp,omitempty"`
}

type AgentBuild struct {
	Original string `json:"original,omitempty"`
}

type Agent struct {
	Build       *AgentBuild `json:"build,omitempty"`
	EphemeralId string      `json:"ephemeral_id,omitempty"`
	Id          string      `json:"id,omitempty"`
	Name        string      `json:"name,omitempty"`
	Type        string      `json:"type,omitempty"`
	Version     string      `json:"version,omitempty"`
}

type AutonomousSystem struct {
	Number       int64         `json:"number,omitempty"`
	Organization *Organization `json:"organization,omitempty"`
}

type Geo struct {
	CityName       string `json:"city_name,omitempty"`
	ContinentCode  string `json:"continent_code,omitempty"`
	ContinentName  string `json:"continent_name,omitempty"`
	CountryIsoCode string `json:"country_iso_code,omitempty"`
	CountryName    string `json:"country_name,omitempty"`
	Location       any    `json:"location,omitempty"`
	Name           string `json:"name,omitempty"`
	PostalCode     string `json:"postal_code,omitempty"`
	RegionIsoCode  string `json:"region_iso_code,omitempty"`
	RegionName     string `json:"region_name,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
}

type Nat struct {
	Ip   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

type Group struct {
	Domain string `json:"domain,omitempty"`
	Id     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
}

type User struct {
	Domain   string `json:"domain,omitempty"`
	Email    string `json:"email,omitempty"`
	FullName string `json:"full_name,omitempty"`
	Group    *Group `json:"group,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Id       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Roles    string `json:"roles,omitempty"`
}

type CloudAccount struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CloudInstance struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CloudMachine struct {
	Type string `json:"type,omitempty"`
}

type CloudProject struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CloudService struct {
	Name string `json:"name,omitempty"`
}

type CloudOriginTargetAccount struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CloudOriginTargetInstance struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CloudOriginTargetMachine struct {
	Type string `json:"type,omitempty"`
}

type CloudOriginTargetProject struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CloudOriginTargetService struct {
	Name string `json:"name,omitempty"`
}

type CloudOriginTarget struct {
	Account          *CloudOriginTargetAccount  `json:"account,omitempty"`
	AvailabilityZone string                     `json:"availability_zone,omitempty"`
	Instance         *CloudOriginTargetInstance `json:"instance,omitempty"`
	Machine          *CloudOriginTargetMachine  `json:"machine,omitempty"`
	Project          *CloudOriginTargetProject  `json:"project,omitempty"`
	Provider         string                     `json:"provider,omitempty"`
	Region           string                     `json:"region,omitempty"`
	Service          *CloudOriginTargetService  `json:"service,omitempty"`
}

type Cloud struct {
	Account          *CloudAccount      `json:"account,omitempty"`
	AvailabilityZone string             `json:"availability_zone,omitempty"`
	Instance         *CloudInstance     `json:"instance,omitempty"`
	Machine          *CloudMachine      `json:"machine,omitempty"`
	Origin           *CloudOriginTarget `json:"origin,omitempty"`
	Project          *CloudProject      `json:"project,omitempty"`
	Provider         string             `json:"provider,omitempty"`
	Region           string             `json:"region,omitempty"`
	Service          *CloudService      `json:"service,omitempty"`
	Target           *CloudOriginTarget `json:"target,omitempty"`
}

type Container struct {
	Id    string `json:"id,omitempty"`
	Image struct {
		Name string `json:"name,omitempty"`
		Tag  string `json:"tag,omitempty"`
	} `json:"image,omitempty"`
	Labels  any    `json:"labels,omitempty"`
	Name    string `json:"name,omitempty"`
	Runtime string `json:"runtime,omitempty"`
}

type DnsAnswer struct {
	Class string `json:"class,omitempty"`
	Data  string `json:"data,omitempty"`
	Name  string `json:"name,omitempty"`
	Ttl   int    `json:"ttl,omitempty"`
	Type  string `json:"type,omitempty"`
}

type DnsQuestion struct {
	net.DomainBreakdown
	Class string `json:"class,omitempty"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
}

type Dns struct {
	Answers      []*DnsAnswer `json:"answers,omitempty"`
	HeaderFlags  any          `json:"header_flags,omitempty"`
	Id           string       `json:"id,omitempty"`
	OpCode       string       `json:"op_code,omitempty"`
	Question     *DnsQuestion `json:"question,omitempty"`
	ResolvedIp   []string     `json:"resolved_ip,omitempty"`
	ResponseCode string       `json:"response_code,omitempty"`
	Type         string       `json:"type,omitempty"`
}

type Error struct {
	Code       string `json:"code,omitempty"`
	Id         string `json:"id,omitempty"`
	Message    string `json:"message,omitempty"`
	StackTrace string `json:"stack_trace,omitempty"`
	Type       string `json:"type,omitempty"`
}

type Email struct {
	Attachments []struct {
		File struct {
			Ext struct {
				Attachment struct {
					FileName              string `json:"file_name,omitempty"`
					MalwareClassification struct {
						Identifier string `json:"identifier,omitempty"`
						Score      int    `json:"score,omitempty"`
						Threshold  int    `json:"threshold,omitempty"`
						Version    string `json:"version,omitempty"`
					} `json:"malware_classification,omitempty"`
				} `json:"attachment,omitempty"`
			} `json:"ext,omitempty"`
		} `json:"file,omitempty"`
	} `json:"attachments,omitempty"`
	Bcc []struct {
		Address string `json:"address,omitempty"`
	} `json:"bcc,omitempty"`
	Cc []struct {
		Address string `json:"address,omitempty"`
	} `json:"cc,omitempty"`
	From struct {
		Address string `json:"address,omitempty"`
	} `json:"from,omitempty"`
	MessageId string `json:"message_id,omitempty"`
	Subject   string `json:"subject,omitempty"`
	To        []struct {
		Address string `json:"address,omitempty"`
	} `json:"to,omitempty"`
}

type Event struct {
	Action        string   `json:"action,omitempty"`
	AgentIdStatus string   `json:"agent_id_status,omitempty"`
	Category      []string `json:"category,omitempty"`
	Code          string   `json:"code,omitempty"`
	Created       string   `json:"created,omitempty"`
	Dataset       string   `json:"dataset,omitempty"`
	Duration      int64    `json:"duration,omitempty"`
	End           string   `json:"end,omitempty"`
	Hash          string   `json:"hash,omitempty"`
	Id            string   `json:"id,omitempty"`
	Ingested      string   `json:"ingested,omitempty"`
	Kind          string   `json:"kind,omitempty"`
	Module        string   `json:"module,omitempty"`
	Original      string   `json:"original,omitempty"`
	Outcome       string   `json:"outcome,omitempty"`
	Provider      string   `json:"provider,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Reference     string   `json:"reference,omitempty"`
	RiskScore     float64  `json:"risk_score,omitempty"`
	Sequence      int      `json:"sequence,omitempty"`
	Severity      int      `json:"severity,omitempty"`
	Start         string   `json:"start,omitempty"`
	Timezone      string   `json:"timezone,omitempty"`
	Type          []string `json:"type,omitempty"`
	Url           string   `json:"url,omitempty"`
}

type File struct {
	Accessed    string   `json:"accessed,omitempty"`
	Attributes  []string `json:"attributes,omitempty"`
	Created     string   `json:"created,omitempty"`
	Ctime       string   `json:"ctime,omitempty"`
	Device      string   `json:"device,omitempty"`
	Directory   string   `json:"directory,omitempty"`
	DriveLetter string   `json:"drive_letter,omitempty"`
	Extension   string   `json:"extension,omitempty"`
	Gid         string   `json:"gid,omitempty"`
	Group       string   `json:"group,omitempty"`
	Hash        struct {
		Md5    string `json:"md5,omitempty"`
		Sha1   string `json:"sha1,omitempty"`
		Sha256 string `json:"sha256,omitempty"`
		Sha512 string `json:"sha512,omitempty"`
	} `json:"hash,omitempty"`
	Inode string `json:"inode,omitempty"`
	Mode  string `json:"mode,omitempty"`
	Mtime string `json:"mtime,omitempty"`
	Owner string `json:"owner,omitempty"`
	Path  string `json:"path,omitempty"`
	Size  int64  `json:"size,omitempty"`
	Type  string `json:"type,omitempty"`
	Uid   string `json:"uid,omitempty"`
}

type Host struct {
	Architecture string   `json:"architecture,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	Id           string   `json:"id,omitempty"`
	Ip           string   `json:"ip,omitempty"`
	Mac          []string `json:"mac,omitempty"`
	Name         string   `json:"name,omitempty"`
	Type         string   `json:"type,omitempty"`
	Uptime       int64    `json:"uptime,omitempty"`
	Os           Os       `json:"os,omitempty"`
}

type HttpRequest struct {
	Body  *Body `json:"body,omitempty"`
	Bytes int   `json:"bytes,omitempty"`
	// NOTE: Custom
	ContentType string       `json:"content_type,omitempty"`
	HttpHeaders *HttpHeaders `json:"http_headers"`
	Id          string       `json:"id,omitempty"`
	Method      string       `json:"method,omitempty"`
	MimeType    string       `json:"mime_type,omitempty"`
	Referrer    string       `json:"referrer,omitempty"`
}

type HttpResponse struct {
	Body  *Body `json:"body,omitempty"`
	Bytes int   `json:"bytes,omitempty"`
	// NOTE: Custom
	ContentType string       `json:"content_type,omitempty"`
	HttpHeaders *HttpHeaders `json:"http_headers,omitempty"`
	MimeType    string       `json:"mime_type,omitempty"`
	// NOTE: Custom
	ReasonPhrase string `json:"reason_phrase,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
}

type Http struct {
	Request  *HttpRequest  `json:"request,omitempty"`
	Response *HttpResponse `json:"response,omitempty"`
	Version  string        `json:"version,omitempty"`
}

type Interface struct {
	Alias string `json:"alias,omitempty"`
	Id    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
}

type Network struct {
	Application string `json:"application,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	CommunityId string `json:"community_id,omitempty"`
	Direction   string `json:"direction,omitempty"`
	ForwardedIp string `json:"forwarded_ip,omitempty"`
	IanaNumber  string `json:"iana_number,omitempty"`
	Inner       any    `json:"inner,omitempty"`
	Name        string `json:"name,omitempty"`
	Packets     int64  `json:"packets,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Type        string `json:"type,omitempty"`
}

type LogOriginFile struct {
	Line int    `json:"line,omitempty"`
	Name string `json:"name,omitempty"`
}

type LogFile struct {
	Path string `json:"path,omitempty"`
}

type LogOrigin struct {
	File     *LogOriginFile `json:"file,omitempty"`
	Function string         `json:"function,omitempty"`
	// NOTE: Custom
	Process *Process `json:"process,omitempty"`
}

type LogSyslogFacility struct {
	Code int    `json:"code,omitempty"`
	Name string `json:"name,omitempty"`
}

type LogSyslogSeverity struct {
	Code int    `json:"code,omitempty"`
	Name string `json:"name,omitempty"`
}

type LogSyslog struct {
	Appname        string             `json:"appname,omitempty"`
	Facility       *LogSyslogFacility `json:"facility,omitempty"`
	Hostname       string             `json:"hostname,omitempty"`
	Msgid          string             `json:"msgid,omitempty"`
	Priority       int                `json:"priority,omitempty"`
	Procid         string             `json:"procid,omitempty"`
	StructuredData map[string]any     `json:"structured_data,omitempty"`
	Version        string             `json:"version,omitempty"`
}

type Log struct {
	LogFile *LogFile   `json:"file,omitempty"`
	Level   string     `json:"level,omitempty"`
	Logger  string     `json:"logger,omitempty"`
	Origin  *LogOrigin `json:"origin,omitempty"`
	Syslog  *LogSyslog `json:"syslog,omitempty"`
}

type ObserverIngressEgress struct {
	Interface *Interface `json:"interface,omitempty"`
	Zone      string     `json:"zone,omitempty"`
}

type Observer struct {
	Egress *ObserverIngressEgress `json:"egress,omitempty"`
	// NOTE: Custom
	Hook         string                 `json:"hook,omitempty"`
	Hostname     string                 `json:"hostname,omitempty"`
	Ingress      *ObserverIngressEgress `json:"ingress,omitempty"`
	Ip           string                 `json:"ip,omitempty"`
	Mac          string                 `json:"mac,omitempty"`
	Name         string                 `json:"name,omitempty"`
	Os           *Os                    `json:"os,omitempty"`
	Product      string                 `json:"product,omitempty"`
	SerialNumber string                 `json:"serial_number,omitempty"`
	Type         string                 `json:"type,omitempty"`
	Vendor       string                 `json:"vendor,omitempty"`
	Version      string                 `json:"version,omitempty"`
}

type Organization struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type Os struct {
	Family   string `json:"family,omitempty"`
	Full     string `json:"full,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	Name     string `json:"name,omitempty"`
	Platform string `json:"platform,omitempty"`
	Type     string `json:"type,omitempty"`
	Version  string `json:"version,omitempty"`
}

type ProcessIo struct {
	Text string `json:"text,omitempty"`
}

type ProcessThreadCapabilities struct {
	Effective []string `json:"effective,omitempty"`
	Permitted []string `json:"permitted,omitempty"`
}

type ProcessThread struct {
	Id   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type Process struct {
	Args             []string       `json:"args,omitempty"`
	ArgsCount        int            `json:"args_count,omitempty"`
	CommandLine      string         `json:"command_line,omitempty"`
	End              string         `json:"end,omitempty"`
	EnvVars          []string       `json:"env_vars,omitempty"`
	Executable       string         `json:"executable,omitempty"`
	ExitCode         int            `json:"exit_code,omitempty"`
	Group            *Group         `json:"group,omitempty"`
	Interactive      bool           `json:"interactive,omitempty"`
	Io               *ProcessIo     `json:"io,omitempty"`
	Name             string         `json:"name,omitempty"`
	Parent           *Process       `json:"parent,omitempty"`
	Pid              int            `json:"pid,omitempty"`
	Previous         *Process       `json:"previous,omitempty"`
	Start            string         `json:"start,omitempty"`
	Threat           *ProcessThread `json:"threat,omitempty"`
	Title            string         `json:"title,omitempty"`
	Uptime           int            `json:"uptime,omitempty"`
	User             *User          `json:"user,omitempty"`
	WorkingDirectory string         `json:"working_directory,omitempty"`
}

type Registry struct {
	Data struct {
		Bytes   int64    `json:"bytes,omitempty"`
		Strings []string `json:"strings,omitempty"`
		Type    string   `json:"type,omitempty"`
	} `json:"data,omitempty"`
	Hive  string `json:"hive,omitempty"`
	Key   string `json:"key,omitempty"`
	Path  string `json:"path,omitempty"`
	Value string `json:"value,omitempty"`
}

type Related struct {
	Hash  []string `json:"hash,omitempty"`
	Hosts []string `json:"hosts,omitempty"`
	Ip    []string `json:"ip,omitempty"`
	User  []string `json:"user,omitempty"`
}

type Rule struct {
	Author      string `json:"author,omitempty"`
	Category    string `json:"category,omitempty"`
	Description string `json:"description,omitempty"`
	Id          string `json:"id,omitempty"`
	License     string `json:"license,omitempty"`
	Name        string `json:"name,omitempty"`
	Reference   string `json:"reference,omitempty"`
	Ruleset     string `json:"ruleset,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	Version     string `json:"version,omitempty"`
}

type Service struct {
	Id    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	State string `json:"state,omitempty"`
	Type  string `json:"type,omitempty"`
}

// NOTE: Custom

type Tcp struct {
	Flags                 []string `json:"flags,omitempty"`
	AcknowledgementNumber *int     `json:"acknowledgement_number,omitempty"`
	SequenceNumber        *int     `json:"sequence_number,omitempty"`
	State                 string   `json:"state,omitempty"`
}

type Threat struct {
	Framework string `json:"framework,omitempty"`
	Indicator struct {
		Confidence  string `json:"confidence,omitempty"`
		Description string `json:"description,omitempty"`
		Email       struct {
			Address string `json:"address,omitempty"`
		} `json:"email,omitempty"`
		File struct {
			Hash struct {
				Md5    string `json:"md5,omitempty"`
				Sha1   string `json:"sha1,omitempty"`
				Sha256 string `json:"sha256,omitempty"`
			} `json:"hash,omitempty"`
			Path string `json:"path,omitempty"`
		} `json:"file,omitempty"`
		Ip   string `json:"ip,omitempty"`
		Type string `json:"type,omitempty"`
		Url  *Url   `json:"url,omitempty"`
	} `json:"indicator,omitempty"`
	Tactic struct {
		Id        string `json:"id,omitempty"`
		Name      string `json:"name,omitempty"`
		Reference string `json:"reference,omitempty"`
	} `json:"tactic,omitempty"`
	Technique struct {
		Id        string `json:"id,omitempty"`
		Name      string `json:"name,omitempty"`
		Reference string `json:"reference,omitempty"`
	} `json:"technique,omitempty"`
}

type Tls struct {
	Client struct {
		Hash struct {
			Sha1   string `json:"sha1,omitempty"`
			Sha256 string `json:"sha256,omitempty"`
		} `json:"hash,omitempty"`
		Issuer    string `json:"issuer,omitempty"`
		NotAfter  string `json:"not_after,omitempty"`
		NotBefore string `json:"not_before,omitempty"`
		Subject   string `json:"subject,omitempty"`
		Version   string `json:"version,omitempty"`
	} `json:"client,omitempty"`
	Server struct {
		Hash struct {
			Sha1   string `json:"sha1,omitempty"`
			Sha256 string `json:"sha256,omitempty"`
		} `json:"hash,omitempty"`
		Issuer    string `json:"issuer,omitempty"`
		NotAfter  string `json:"not_after,omitempty"`
		NotBefore string `json:"not_before,omitempty"`
		Subject   string `json:"subject,omitempty"`
		Version   string `json:"version,omitempty"`
	} `json:"server,omitempty"`
}

type Url struct {
	net.DomainBreakdown
	Domain    string `json:"domain,omitempty"`
	Extension string `json:"extension,omitempty"`
	Fragment  string `json:"fragment,omitempty"`
	Full      string `json:"full,omitempty"`
	Original  string `json:"original,omitempty"`
	Password  string `json:"password,omitempty"`
	Path      string `json:"path,omitempty"`
	Port      int    `json:"port,omitempty"`
	Query     string `json:"query,omitempty"`
	Scheme    string `json:"scheme,omitempty"`
	Username  string `json:"username,omitempty"`
}

type UserAgentDevice struct {
	Name string `json:"name,omitempty"`
}

type UserAgent struct {
	Device   *UserAgentDevice `json:"device,omitempty"`
	Name     string           `json:"name,omitempty"`
	Original string           `json:"original,omitempty"`
	Os       *Os              `json:"os,omitempty"`
	Version  string           `json:"version,omitempty"`
}

type VulnerabilityScanner struct {
	Vendor string `json:"vendor,omitempty"`
}

type VulnerabilityScore struct {
	Base          float64 `json:"base,omitempty"`
	Environmental float64 `json:"environmental,omitempty"`
	Temporal      float64 `json:"temporal,omitempty"`
	Version       string  `json:"version,omitempty"`
}

type Vulnerability struct {
	Category       string                `json:"category,omitempty"`
	Classification string                `json:"classification,omitempty"`
	Description    string                `json:"description,omitempty"`
	Enumeration    string                `json:"enumeration,omitempty"`
	Id             string                `json:"id,omitempty"`
	Reference      string                `json:"reference,omitempty"`
	ReportId       string                `json:"report_id,omitempty"`
	Scanner        *VulnerabilityScanner `json:"scanner,omitempty"`
	Score          *VulnerabilityScore   `json:"score,omitempty"`
	Severity       string                `json:"severity,omitempty"`
}

// NOTE: Custom

type WhoisRequest struct {
	Body *Body  `json:"body,omitempty"`
	Id   string `json:"id,omitempty"`
}

// NOTE: Custom

type WhoisResponse struct {
	Body *Body `json:"body,omitempty"`
}

// NOTE: Custom

type Whois struct {
	Request  *WhoisRequest  `json:"request,omitempty"`
	Response *WhoisResponse `json:"response,omitempty"`
}

type X509 struct {
	AlternateNames []string `json:"alternate_names,omitempty"`
	Issuer         struct {
		CommonName          string `json:"common_name,omitempty"`
		Country             string `json:"country,omitempty"`
		Organization        string `json:"organization,omitempty"`
		OrganizationalUnit  string `json:"organizational_unit,omitempty"`
		StateOrProvinceName string `json:"state_or_province_name,omitempty"`
	} `json:"issuer,omitempty"`
	NotAfter           string `json:"not_after,omitempty"`
	NotBefore          string `json:"not_before,omitempty"`
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	Subject            struct {
		CommonName          string `json:"common_name,omitempty"`
		Country             string `json:"country,omitempty"`
		Organization        string `json:"organization,omitempty"`
		OrganizationalUnit  string `json:"organizational_unit,omitempty"`
		StateOrProvinceName string `json:"state_or_province_name,omitempty"`
	} `json:"subject,omitempty"`
	VersionNumber int `json:"version_number,omitempty"`
}
