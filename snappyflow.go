package sfapmlib

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/shirou/gopsutil/host"
	"gopkg.in/yaml.v3"
)

func init() {
	// first check if the environment variables are set
	sfKey, projectName, appName := getFromEnvVariables()
	if sfKey == "" || projectName == "" || appName == "" {
		// the environment variables are not set
		// so take values from config file
		fmt.Println("Cannot read values from environment variables. So taking values from config.yaml file")
		err := InitConfig()
		if err != nil {
			fmt.Println("Please check if a valid config.yaml is present")
			fmt.Println("Or set the required environment variables")
		}
	} else {
		// all the required environment variables are set
		// so proceed with these values
		err := InitEnv(sfKey, projectName, appName)
		if err != nil {
			fmt.Println("Please check if correct values are provided in the environment variables")
		}
	}
}

// LoadConfigFromFile loads the config from config.yaml
func LoadConfigFromFile(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// InitConfig sets the values from sfagent's config.yaml
func InitConfig() error {
	var configPath string
	var osType string
	var config *Config
	var configerr error

	host, err := host.Info()
	if err == nil && host != nil {
		osType = host.OS
	} else {
		return err
	}
	if osType == "windows" {
		configPath = WindowsConfigPath
	} else {
		configPath = LinuxConfigPath
	}
	config, configerr = LoadConfigFromFile(configPath) // gets only profile key and tags
	if configerr != nil {
		return configerr
	}

	traceServerURL, profileID, err := getProfileData(config.SnappyFlowKey)
	if err != nil {
		return err
	}
	err = setEnvVariables(traceServerURL, profileID, config.Tags)
	if err != nil {
		return err
	}

	return nil
}

// InitEnv sets the values from environment variables
func InitEnv(sfKey string, projectName string, appName string) error {
	tags := &Tags{
		ProjectName: projectName,
		AppName:     appName,
	}

	traceServerURL, profileID, err := getProfileData(sfKey)
	if err != nil {
		return err
	}
	err = setEnvVariables(traceServerURL, profileID, *tags)
	if err != nil {
		return err
	}

	return nil
}

func getProfileData(key string) (string, string, error) {
	decryptedKey, err := base64.StdEncoding.DecodeString(EncryptedKey)
	if err != nil {
		return "", "", err
	}
	data, err := decryptKey(key, decryptedKey)
	if err != nil {
		return "", "", err
	}
	var keydata SnappyFlowKeyData
	err = json.Unmarshal([]byte(data), &keydata)
	if err != nil {
		return "", "", err
	}
	return keydata.TraceServer, keydata.ProfileID, nil
}

func setEnvVariables(traceURL string, profileID string, tags Tags) error {
	globalLabels := fmt.Sprintf(GlobalLabels, tags[ProjectName], tags[AppName], profileID)
	err := os.Setenv(ElasticAPMServerURL, traceURL)
	err = os.Setenv(ElasticAPMGlobalLabels, globalLabels)
	if err != nil {
		return err
	}

	return nil
}

func getFromEnvVariables() (string, string, string) {
	sfKey := os.Getenv(SfProfileKey)
	projectName := os.Getenv(SfProjectName)
	appName := os.Getenv(SfAppName)
	return sfKey, projectName, appName
}

func decryptKey(rawData string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		return "", err
	}
	dnData, err := aesCBCDecrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(dnData), nil
}

func aesCBCDecrypt(encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	if len(encryptData)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(encryptData, encryptData)
	encryptData = unpad(encryptData)
	return encryptData, nil
}

func unpad(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
