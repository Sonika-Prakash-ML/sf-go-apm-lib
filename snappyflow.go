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

	// "os/exec"

	"log"
	"path/filepath"

	"github.com/shirou/gopsutil/host"
	"gopkg.in/yaml.v3"
)

var Info *log.Logger
var Debug *log.Logger
var Error *log.Logger
var Warn *log.Logger

func init() {
	fmt.Println("sfapmpkg init()")
	filePath, _ := filepath.Abs("C:\\Users\\Sonika.Prakash\\GitHub\\goji web app\\web.log")
	openLogFile, _ := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	Info = log.New(openLogFile, "\tINFO\t", log.Ldate|log.Ltime|log.Lmsgprefix|log.Lshortfile)
	Debug = log.New(openLogFile, "\tDEBUG\t", log.Ldate|log.Ltime|log.Lmsgprefix|log.Lshortfile)
	Error = log.New(openLogFile, "\tERROR\t", log.Ldate|log.Ltime|log.Lmsgprefix|log.Lshortfile)
	Warn = log.New(openLogFile, "\tWARN\t", log.Ldate|log.Ltime|log.Lmsgprefix|log.Lshortfile)

	Debug.Println("Inside sfapmpkg init()")

	// os.Setenv("ELASTIC_APM_SERVER_URL", "http://10.11.100.206:8201")
	// os.Setenv("ELASTIC_APM_GLOBAL_LABELS", "_tag_projectName=test-project,_tag_appName=test-app,_tag_profileId=jnanhkmf")

	// first check if the environment variables are set
	sfKey, projectName, appName := getFromEnvVariables()
	if sfKey == "" || projectName == "" || appName == "" {
		// the environment variables are not set
		// so take values from config file
		fmt.Println("Cannot read values from environment variables. So taking values from config.yaml file")
		err := InitConfig()
		if err != nil {
			fmt.Println("Encountered error while trying to read from config.yaml file:", err)
			fmt.Println("Please check if a valid config.yaml is present")
			fmt.Println("Or set the required environment variables")
		}
	} else {
		// all the required environment variables are set
		// so proceed with these values
		err := InitEnv(sfKey, projectName, appName)
		if err != nil {
			fmt.Println("Encountered error while trying to set from environment variables:", err)
			fmt.Println("Please check if correct values are provided in the environment variables")
		}
	}

	Debug.Println("End of sfapmpkg init()")
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

// InitDefault sets the values from sfagent's config.yaml
func InitConfig() error {
	var configPath string
	var osType string
	var config *Config
	var configerr error

	host, err := host.Info()
	if err == nil && host != nil {
		osType = host.OS
	} else {
		// fmt.Println("Error while getting the host info:", err)
		return err
	}
	if osType == "windows" {
		configPath = WindowsConfigPath
	} else {
		configPath = LinuxConfigPath
	}
	config, configerr = LoadConfigFromFile(configPath) // gets only profile key and tags
	if configerr != nil {
		// fmt.Println("Error while reading config file:", configerr)
		return configerr
	}
	// fmt.Println("profile key:", config.SnappyFlowKey)
	// fmt.Println("tags:", config.Tags)

	traceServerURL, profileID, err := getProfileData(config.SnappyFlowKey)
	if err != nil {
		// fmt.Println("Error while decrypting key:", err)
		return err
	}
	// Debug.Println("trace url:", traceServerURL)
	// Debug.Println("profile id:", profileID)
	err = setEnvVariables(traceServerURL, profileID, config.Tags)
	if err != nil {
		return err
	}
	// Debug.Println("tags:", config.Tags)

	return nil
}

// Init sets the values from environment variables
func InitEnv(sfKey string, projectName string, appName string) error {
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
