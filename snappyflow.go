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

// InitDefault sets the values from config.yaml
func (sf *SfData) InitDefault() {
	var configPath string
	var osType string
	var config *Config
	var configerr error

	host, err := host.Info()
	if err == nil && host != nil {
		osType = host.OS
	}
	if osType == "windows" {
		configPath = WindowsConfigPath
	} else {
		configPath = LinuxConfigPath
	}
	config, configerr = LoadConfigFromFile(configPath) // gets only profile key and tags
	if configerr != nil {
		fmt.Println("Error while reading config file:", configerr)
		os.Exit(1)
	}
	fmt.Println("profile key:", config.SnappyFlowKey)
	fmt.Println("tags:", config.Tags)

	traceServerURL, profileID, err := GetProfileData(config.SnappyFlowKey)
	if err != nil {
		fmt.Println("Error while decrypting key:", err)
		os.Exit(1)
	}
	err = SetEnvVariables(traceServerURL, profileID, config.Tags)
}

func GetProfileData(key string) (string, string, error) {
	decryptedKey, err := base64.StdEncoding.DecodeString(EncryptedKey)
	if err != nil {
		fmt.Println("Unable to decrypyt EncryptedKey:", err)
		return "", "", err
	}
	fmt.Println("decryptedKey:", string(decryptedKey))
	data, err := DecryptKey(key, decryptedKey)
	if err != nil {
		fmt.Println("unable to decrypt key:", err)
		return "", "", err
	}
	var keydata SnappyFlowKeyData
	err = json.Unmarshal([]byte(data), &keydata)
	if err != nil {
		fmt.Println("unable to unmarshal key data:", err)
		return "", "", err
	}
	fmt.Println("trace server url:", keydata.TraceServer)
	fmt.Println("profile id:", keydata.ProfileID)
	return keydata.TraceServer, keydata.ProfileID, nil
}

func SetEnvVariables(traceURL string, profileID string, tags Tags) error {
	globalLabels := fmt.Sprintf(GlobalLabels, tags[ProjectName], tags[AppName], profileID)
	fmt.Println("global labels:", globalLabels)

	return nil
}

func DecryptKey(rawData string, key []byte) (string, error) {
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
