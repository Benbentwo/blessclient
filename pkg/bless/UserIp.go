package bless

import (
	"github.com/Benbentwo/blessclient/pkg/util"
	"github.com/Benbentwo/utils/log"
	"io/ioutil"
	"net/http"
	"strings"

	"time"
)

type UserIP struct {
	Fresh        bool
	CurrentIP    string
	CacheFile    BlessCacheFile
	MaxCacheTime time.Duration
	IpUrls       []string
	FixedIp      bool
	CurrentIp    string
}

func (uip *UserIP) GetIp() string {
	if uip.Fresh && uip.CurrentIP != "" {
		return uip.CurrentIP
	}
	lastip := uip.CacheFile.Cache.LastIp
	lastiptime := uip.CacheFile.Cache.LastIpCheckTime

	if lastiptime != "" && util.StringToTime(lastiptime).Add(uip.MaxCacheTime).After(time.Now()) {
		return lastip
	}
	uip.RefreshIp()
	return uip.CurrentIP
}

func (uip *UserIP) RefreshIp() {
	log.Logger().Debugln("Getting current public IP")
	ip := ""
	for _, url := range uip.IpUrls {
		if ip != "" {
			break
		} else {
			ip = uip.FetchIp(url)
		}
	}
	if ip == "" {
		log.Logger().Fatalf("Couldn't Refresh public IP")
	}

	uip.CurrentIP = ip
	uip.Fresh = true
	uip.CacheFile.Cache.LastIp = uip.CurrentIP
	uip.CacheFile.Cache.LastIpCheckTime = string(time.Now().Unix())
	err := uip.CacheFile.SaveCache(DefaultBlessCacheLocation)
	if err != nil {
		log.Logger().Fatalf("failed to save cache: %s", err)
	}
}

func (uip *UserIP) FetchIp(url string) string {
	httpclient := http.Client{
		Timeout: 2 * time.Second,
	}
	resp, err := httpclient.Get(url)
	if err != nil {
		log.Logger().Errorf("GET failed to `%s` %s", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		log.Logger().Debugf("response code from fetch %s", resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Logger().Errorf("parsing responsed failed: %s", err)
		}

		return strings.TrimSpace(string(body))
	}
	return ""
}
