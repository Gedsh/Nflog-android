package main

import (
	"flag"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dchest/safefile"
)

var pidFile = flag.String("pidfile", "", "Store the PID into a file")

func PidFileCreate() error {
	var file = getPidFilePath()
	if file == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(*file), 0755); err != nil {
		return err
	}
	return safefile.WriteFile(*file, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func PidFileRemove() error {
	var file = getPidFilePath()
	if file == nil {
		return nil
	}

	return os.Remove(*file)
}

func getPidFilePath() *string {
	var file string
	if pidFile == nil || len(*pidFile) == 0 {
		return nil
	} else {
		file = *pidFile
	}

	return &file
}
