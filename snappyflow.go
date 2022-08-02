package sfapmpkg

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

// InitDefault sets the values from sfagent's config.yaml
func InitDefault() {
	var configPath string
	var osType string
	var config *Config
	var configerr error

	host, err := host.Info()
	if err == nil && host != nil {
		osType = host.OS
	} else {
		// fmt.Println("Error while getting the host info:", err)
		os.Exit(1)
	}
	if osType == "windows" {
		configPath = WindowsConfigPath
	} else {
		configPath = LinuxConfigPath
	}
	config, configerr = LoadConfigFromFile(configPath) // gets only profile key and tags
	if configerr != nil {
		// fmt.Println("Error while reading config file:", configerr)
		os.Exit(1)
	}
	// fmt.Println("profile key:", config.SnappyFlowKey)
	// fmt.Println("tags:", config.Tags)

	traceServerURL, profileID, err := getProfileData(config.SnappyFlowKey)
	if err != nil {
		// fmt.Println("Error while decrypting key:", err)
		os.Exit(1)
	}
	err = setEnvVariables(traceServerURL, profileID, config.Tags)
	if err != nil {
		os.Exit(1)
	}
}

// Init sets the values from environment variables
func Init(sfKey string, projectName string, appName string) {
	// sfKey, projectName, appName := getFromEnvVariables()
	tags := &Tags{
		ProjectName: projectName,
		AppName:     appName,
	}
	// fmt.Println("profile key:", sfKey)
	// fmt.Println("tags:", tags)

	traceServerURL, profileID, err := getProfileData(sfKey)
	if err != nil {
		// fmt.Println("Error while decrypting key:", err)
		os.Exit(1)
	}
	err = setEnvVariables(traceServerURL, profileID, *tags)
	if err != nil {
		os.Exit(1)
	}
}

func getProfileData(key string) (string, string, error) {
	decryptedKey, err := base64.StdEncoding.DecodeString(EncryptedKey)
	if err != nil {
		// fmt.Println("Unable to decrypyt EncryptedKey:", err)
		return "", "", err
	}
	// fmt.Println("decryptedKey:", string(decryptedKey))
	data, err := decryptKey(key, decryptedKey)
	if err != nil {
		// fmt.Println("unable to decrypt key:", err)
		return "", "", err
	}
	var keydata SnappyFlowKeyData
	err = json.Unmarshal([]byte(data), &keydata)
	if err != nil {
		// fmt.Println("unable to unmarshal key data:", err)
		return "", "", err
	}
	// fmt.Println("trace server url:", keydata.TraceServer)
	// fmt.Println("profile id:", keydata.ProfileID)
	return keydata.TraceServer, keydata.ProfileID, nil
}

func setEnvVariables(traceURL string, profileID string, tags Tags) error {
	globalLabels := fmt.Sprintf(GlobalLabels, tags[ProjectName], tags[AppName], profileID)
	// fmt.Println("global labels:", globalLabels)

	// err := os.Setenv("TEST_APM_SERVER_URL", traceURL)
	// err = os.Setenv("TEST_APM_GLOBAL_LABELS", globalLabels)
	err := os.Setenv(ElasticAPMServerURL, traceURL)
	err = os.Setenv(ElasticAPMGlobalLabels, globalLabels)
	if err != nil {
	}

	// _, cmdErr := exec.Command("cmd.exe", "/C", "setx", ElasticAPMServerURL, traceURL, "/m").Output()
	// if cmdErr != nil {
	// 	// fmt.Println("error while setting environment variables:", err)
	// 	return cmdErr
	// }
	// _, cmdErr = exec.Command("cmd.exe", "/C", "setx", ElasticAPMGlobalLabels, globalLabels, "/m").Output()
	// if cmdErr != nil {
	// 	// fmt.Println("error while setting environment variables:", err)
	// 	return cmdErr
	// }
	// fmt.Println("url env:", os.Getenv("TEST_APM_SERVER_URL"))
	// fmt.Println("tags env:", os.Getenv("TEST_APM_GLOBAL_LABELS"))

	return nil
}

// func getFromEnvVariables() (string, string, string) {
// 	sfKey := os.Getenv(SfProfileKey)
// 	projectName := os.Getenv(SfProjectName)
// 	appName := os.Getenv(SfAppName)
// 	return sfKey, projectName, appName
// }

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
