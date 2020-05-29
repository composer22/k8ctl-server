package server

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os/exec"
)

// createV4UUID returns a V4 RFC4122 compliant UUID.
func createV4UUID() string {
	u := make([]byte, 16)
	rand.Read(u)
	// 13th char must be 4 and 17th must be in [89AB]
	u[8] = (u[8] | 0x80) & 0xBF
	u[6] = (u[6] | 0x40) & 0x4F
	return fmt.Sprintf("%X-%X-%X-%X-%X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}

// execCmd executes an os command and formats any output from stdout/err.
func execCmd(cmd *exec.Cmd) (string, error) {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := stdout.String()
	if err := stderr.String(); err != "" {
		return "", errors.New(err)
	}
	return result, err
}
