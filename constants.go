package sfapmlib

// sf decryption key
const (
	EncryptedKey = "U25hcHB5RmxvdzEyMzQ1Ng=="
)

// tag values
const (
	ProjectName = "projectName"
	AppName     = "appName"
)

// config.yaml paths
const (
	WindowsConfigPath = "C:\\Program Files (x86)\\Sfagent\\config.yaml"
	LinuxConfigPath   = "/opt/sfagent/config.yaml"
)

// apm environment variable values
const (
	GlobalLabels           = "_tag_projectName=%s,_tag_appName=%s,_tag_profileId=%s"
	ElasticAPMServerURL    = "ELASTIC_APM_SERVER_URL"
	ElasticAPMGlobalLabels = "ELASTIC_APM_GLOBAL_LABELS"
	SfProjectName          = "SF_PROJECT_NAME"
	SfAppName              = "SF_APP_NAME"
	SfProfileKey           = "SF_PROFILE_KEY"
)
