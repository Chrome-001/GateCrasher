package fuzzer

import (
	"os"
	"testing"

	"github.com/gate-crasher/gate-crasher/internal/banner"
)

func TestMain(m *testing.M) {
	banner.Print()
	os.Exit(m.Run())
}
