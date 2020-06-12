package bless

import (
	"encoding/json"
	"github.com/Benbentwo/utils/log"
	"github.com/Benbentwo/utils/util"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sigs.k8s.io/yaml"
)

type BlessCacheFile struct {
	Enabled  bool
	filepath string
	filename string
	Cache    *BlessCache
	dirty    bool
}

type BlessCache struct {
	Username        string `json:"username"`
	LastUpdated     string `json:"last_updated"`
	Userarn         string `json:"userarn"`
	CertIp          string `json:"certip"`
	LastIp          string `json:"lastip"`
	LastIpCheckTime string `json:"lastipchecktime"`
}

const (
	DefaultBlessCacheLocation = "~/.bless/session/bless_cache.json"
)

func (bc *BlessCacheFile) init(filepath string, filename string, mode bool) {
	bc.Enabled = mode
	bc.filename = filename
	bc.filepath = filepath
	bc.Cache = nil
	bc.dirty = false
}

func (bc *BlessCacheFile) Get(key string) (string, error) {
	if !bc.Enabled {
		log.Logger().Debugf("BlessCache get disabled")
		return "", errors.New("cache get disabled")
	}

}

func LoadCache(filepath string) (*BlessCache, error) {
	expandedConfPath, err := homedir.Expand(filepath)
	if err != nil {
		return nil, errors.Wrap(err, "could not expand homedir")
	}

	b, err := ioutil.ReadFile(expandedConfPath)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read config at %s", filepath)
	}

	conf := &BlessCache{}
	err = json.Unmarshal(b, conf)
	if err != nil {
		return nil, errors.Wrapf(err, "could not yaml unmarshal config at %s", filepath)
	}
	return conf, nil
}
func (bc *BlessCacheFile) LoadCache() error {
	bc.Cache = nil
	cacheFilePath := filepath.Join(bc.filepath, bc.filename)
	if ex, _ := util.FileExists(cacheFilePath); ex {
		cache, err := LoadCache(cacheFilePath)
		if err != nil {
			log.Logger().Errorf("loading cache: %s", err)
			return err
		}
		bc.Cache = cache
	}
	return nil

}

func (bc *BlessCacheFile) SaveCache(configPath string) error {
	if configPath == "" {
		configPath = DefaultBlessCacheLocation
	}
	configPath, err := GetOrCreateCachePath(configPath)
	if err != nil {
		return err
	}

	b, err := yaml.Marshal(bc)
	if err != nil {
		return errors.Wrap(err, "Error marshaling bless cache")
	}

	err = ioutil.WriteFile(configPath, b, 0644)
	if err != nil {
		return errors.Wrapf(err, "Could not write config to %s", configPath)
	}
	log.Logger().Infof("Config written to %s", configPath)
	return nil
}

func GetOrCreateCachePath(configPath string) (string, error) {
	expandedConfigFile, err := homedir.Expand(configPath)
	if err != nil {

		return "", errors.Wrapf(err, "could not expand %s", expandedConfigFile)
	}
	blessclientDir := path.Dir(expandedConfigFile)

	err = os.MkdirAll(blessclientDir, 0755) // #nosec
	if err != nil {
		return "", errors.Wrapf(err, "Could not create client config dir %s", blessclientDir)
	}
	return expandedConfigFile, nil
}

// def loadCache(self):
// self.cache = {}
// cache_file_path = os.path.join(self.filepath, self.filename)
// if os.path.isfile(cache_file_path):
// with open(cache_file_path, 'r') as cache:
// try:
// self.cache = json.load(cache)
// except:
// logging.error("Corrupted cache, using empty cache")
// logging.debug("BlessCache loaded: {}".format(self.cache))

// def get(self, key):
// if self.mode != self.CACHEMODE_ENABLED:
// logging.debug("BlessCache get disabled")
// return None
// value = None
// if self.cache is None:
// self.loadCache()
// if key in self.cache.keys():
// value = self.cache[key]
// return value
//
// def set(self, key, value):
// if self.cache is None:
// self.loadCache()
// self.dirty = True
// self.cache[key] = value
//
// def save(self):
// if self.dirty and self.mode != self.CACHEMODE_DISABLED:
// self.saveCache()
//
// def loadCache(self):
// self.cache = {}
// cache_file_path = os.path.join(self.filepath, self.filename)
// if os.path.isfile(cache_file_path):
// with open(cache_file_path, 'r') as cache:
// try:
// self.cache = json.load(cache)
// except:
// logging.error("Corrupted cache, using empty cache")
// logging.debug("BlessCache loaded: {}".format(self.cache))
//
// def saveCache(self):
// if not os.path.exists(self.filepath):
// os.makedirs(self.filepath)
// cache_file_path = os.path.join(self.filepath, self.filename)
// with open(cache_file_path, 'w') as cache:
// json.dump(self.cache, cache)
// logging.debug("BlessCache saved")
