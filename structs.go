package sfapmpkg

// SfData holds the profile data and tags
type SfData struct {
	projectName string
	appName     string
	profileData string
}

// Tags holds the project name and app name as provided in config.yaml
type Tags map[string]string

// Config stores the key and tags from config.yaml
type Config struct {
	SnappyFlowKey string `json:"key,omitempty" yaml:"key,omitempty"`
	Tags          Tags   `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// SnappyFlowKeyData struct holds content after decryption
type SnappyFlowKeyData struct {
	Host        string `json:"host"`
	URL         string `json:"url"`
	Port        int    `json:"port"`
	ApmServer   string `json:"apm_server"`
	ApmPort     int    `json:"apm_port"`
	Type        string `json:"type"`
	ProfileID   string `json:"profile_id"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Protocol    string `json:"protocol"`
	Token       string `json:"token"`
	Owner       string `json:"owner"`
	ES_7x       bool   `json:"es_7x"`
	TraceServer string `json:"trace_server_url"`
	KeyVersion  string `json:"version"`
	KeyTime     int    `json:"time"`
}
