package util

import (
	"github.com/Benbentwo/utils/log"
	"strconv"
	"strings"
	"time"
)

func StringToTime(s string) time.Time {
	arr := strings.Split(s, ".")
	sec, err := strconv.ParseInt(arr[0], 10, 64)
	if err != nil {
		log.Logger().Fatalf("string to time failed: %s", err)
		return time.Time{}
	}
	var nano int64
	if len(arr) >= 2 {
		nano, err = strconv.ParseInt(arr[1], 10, 64)
		if err != nil {
			log.Logger().Fatalf("string to time failed: %s", err)
			return time.Time{}
		}
	}
	return time.Unix(sec, nano)
}
