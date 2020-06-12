package util

import (
	"os"
)

func UnsetEnvTokens() error {
	err := os.Unsetenv("AWS_ACCESS_KEY_ID")
	if err != nil {
		return err
	}
	err = os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	if err != nil {
		return err
	}
	err = os.Unsetenv("AWS_SESSION_TOKEN")
	if err != nil {
		return err
	}
	err = os.Unsetenv("AWS_SECURITY_TOKEN")
	if err != nil {
		return err
	}
	err = os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
	return err
}
