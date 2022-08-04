package sfapmlib

// Tags holds the project name and app name as provided in config.yaml
type Tags map[string]string

// Config stores the key and tags from config.yaml
type Config struct {
	SnappyFlowKey string `json:"key,omitempty" yaml:"key,omitempty"`
	Tags          Tags   `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// SnappyFlowKeyData struct holds content after decryption
type SnappyFlowKeyData struct {
	ProfileID   string `json:"profile_id"`
	TraceServer string `json:"trace_server_url"`
}
