package utils

import (
	"syscall"
)

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func GetHostPidNamespaceID() (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat("/proc/1/ns/pid", &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}
