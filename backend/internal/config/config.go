package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func Duration(name string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return fallback, nil
	}
	d, e := time.ParseDuration(v)
	if e != nil || d < time.Minute || d > 30*24*time.Hour {
		return 0, fmt.Errorf("invalid %s", name)
	}
	return d, nil
}
func RetentionDays() (int, error) {
	v := os.Getenv("RETENTION_DAYS")
	if v == "" {
		return 0, nil
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < 0 || n > 36500 {
		return 0, fmt.Errorf("invalid RETENTION_DAYS")
	}
	return n, nil
}
