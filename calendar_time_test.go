package libmagic

import (
	"github.com/yizhibenpao/go-libmagic/internal/softprobe"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCalendarTimesWithoutReference(t *testing.T) {
	count := 0
	for _, tc := range softprobe.CalendarTimes() {
		if !strings.HasPrefix(tc.Name, "date-qdate-") {
			continue
		}
		count++
		want := strings.TrimSuffix(strings.TrimPrefix(tc.File[0].Value, "root value=["), "]")
		v := binary.LittleEndian.Uint64(tc.Data[8:])
		if got := formatTime(v); got != want {
			t.Errorf("%s: %q, want %q", tc.Name, got, want)
		}
	}
	if count != 24 {
		t.Fatalf("frozen scalar checks: %d, want 24", count)
	}
}

func TestCalendarYearBoundariesWithoutReference(t *testing.T) {
	// Independently frozen glibc-2.35 gmtime_r/asctime_r digest: first and
	// last seconds of every calendar year, including both rejection bounds.
	h := sha256.New()
	count := 0
	for year := -1001; year <= 10001; year++ {
		for _, end := range []bool{false, true} {
			tm := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
			if end {
				tm = time.Date(year, 12, 31, 23, 59, 59, 0, time.UTC)
			}
			sec := tm.Unix()
			fmt.Fprintf(h, "%d=%s\n", sec, formatTime(uint64(sec)))
			count++
		}
	}
	if count != 22006 || fmt.Sprintf("%x", h.Sum(nil)) != "b657eb5331a4071f8622764228349534c902bc99ea3c74b015733194678c3665" {
		t.Fatalf("%d calendar boundaries: digest %x", count, h.Sum(nil))
	}
}

func TestCalendarLocalWithoutReference(t *testing.T) {
	zone := os.Getenv("LIBMAGIC_TEST_CALENDAR_ZONE")
	if zone == "" {
		for _, zone := range []string{"UTC", "Asia/Shanghai", "America/New_York", "Pacific/Kiritimati", "Etc/GMT+12"} {
			t.Run(zone, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestCalendarLocalWithoutReference$")
				cmd.Env = append(os.Environ(), "LIBMAGIC_TEST_CALENDAR_ZONE="+zone)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%v: %s", err, out)
				}
			})
		}
		return
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		t.Fatal(err)
	}
	// Isolated test process only; production never overrides time.Local.
	// This also makes the private checks deterministic on Windows, where
	// time.Local does not read the Unix TZ environment variable.
	time.Local = loc
	count := 0
	for _, tc := range softprobe.LocalCalendarTimes() {
		if tc.Zone != zone {
			continue
		}
		count++
		if got := formatTimeFlags(tc.Value, timeLocal); got != tc.Want {
			t.Errorf("%s seconds %d: %q, want %q", zone, int64(tc.Value), got, tc.Want)
		}
	}
	if count != 28 {
		t.Fatalf("%s scalar checks: %d, want 28", zone, count)
	}
}
