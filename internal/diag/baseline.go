package diag

import "time"

type Level string

const (
	LevelOptimal Level = "OPTIMAL"
	LevelNormal  Level = "NORMAL"
	LevelWarning Level = "WARNING"
	LevelError   Level = "CRITICAL"
)

const (
	MaxWifiLatency    = 5 * time.Millisecond
	MaxDNSLatency     = 60 * time.Millisecond
	MaxAsiaTCPRTT     = 90 * time.Millisecond
	MaxUSTCPRTT       = 180 * time.Millisecond
	MaxTLSLatency     = 180 * time.Millisecond
	MaxNormalTTFB     = 2000 * time.Millisecond
	SevereServerQueue = 3000 * time.Millisecond
)
