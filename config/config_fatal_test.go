package config

import (
	"os"
	"os/exec"
	"testing"
)

// These tests exercise log.Fatal(f) branches, which call os.Exit and would
// otherwise kill the test binary. The standard Go idiom is to re-exec the
// test binary itself with a marker env var set, run only the fatal call in
// that child process, and assert it exits non-zero from the parent.
//
// This covers three representative shapes rather than every log.Fatal call
// site in the package: a missing required config value (requireStringConfig
// — reused 8x inside Load(), so this proves the shape of all of them), a
// corrupt/unparsable key file (readKeyFile's own fatal branch, reached via
// loadPrivateKey), and a syntactically valid but wrong-key-type PEM block
// (loadPrivateKey's actual type-assertion logic, not just I/O). Every other
// log.Fatal in this package (parseIntConfig/parseFloatConfig's fatal
// branches, the mirrored branches in loadPublicKey, InitSentry, and
// server.go's Start/gracefulShutdown) is either mechanically identical to
// one of these three shapes or not practical to trigger deterministically
// without crossing into integration-test territory for little extra
// confidence — see the design notes in this repo's test-coverage work.

const beCrasherEnv = "BE_CRASHER"

func runCrasherSubprocess(t *testing.T, testName string, extraEnv ...string) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(append(os.Environ(), beCrasherEnv+"=1"), extraEnv...)
	return cmd.Run()
}

func assertExitedNonZero(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the subprocess to exit non-zero (log.Fatal should have called os.Exit), but it exited 0")
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("subprocess failed to start/run: %v", err)
	}
}

func TestRequireStringConfig_FatalOnMissing(t *testing.T) {
	const key = "TEST_REQUIRE_STRING_CONFIG_MISSING_FATAL"
	if os.Getenv(beCrasherEnv) == "1" {
		os.Unsetenv(key)
		requireStringConfig(key)
		return
	}

	err := runCrasherSubprocess(t, "TestRequireStringConfig_FatalOnMissing")
	assertExitedNonZero(t, err)
}

func TestLoadPrivateKey_FatalOnCorruptFile(t *testing.T) {
	if os.Getenv(beCrasherEnv) == "1" {
		loadPrivateKey(os.Getenv("TEST_KEY_FILE"))
		return
	}

	dir := t.TempDir()
	corruptFile := writeCorruptPEMFile(t, dir)

	err := runCrasherSubprocess(t, "TestLoadPrivateKey_FatalOnCorruptFile", "TEST_KEY_FILE="+corruptFile)
	assertExitedNonZero(t, err)
}

func TestLoadPrivateKey_FatalOnWrongKeyType(t *testing.T) {
	if os.Getenv(beCrasherEnv) == "1" {
		loadPrivateKey(os.Getenv("TEST_KEY_FILE"))
		return
	}

	dir := t.TempDir()
	wrongTypeFile := writeWrongTypePrivateKeyFile(t, dir)

	err := runCrasherSubprocess(t, "TestLoadPrivateKey_FatalOnWrongKeyType", "TEST_KEY_FILE="+wrongTypeFile)
	assertExitedNonZero(t, err)
}
