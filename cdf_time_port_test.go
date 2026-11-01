package libmagic

import (
	"testing"
	"time"
)

func resetCDFMktimeState() {
	cdfMktimeState.Lock()
	cdfMktimeState.offset = 0
	cdfMktimeState.Unlock()
}

func TestCDFTimeUsesFILE541CalendarAndUTCMktime(t *testing.T) {
	oldLocal := time.Local
	defer func() { time.Local = oldLocal }()
	time.Local = time.UTC
	resetCDFMktimeState()
	defer resetCDFMktimeState()

	if got := cdfTime(0x01A5E403C2D59C00); got != "Sun Apr 24 01:30:00 1977" {
		t.Fatalf("UTC FILE5_41 timestamp = %q", got)
	}
}

func TestCDFMktimeHonorsFILE541StandardTimeRequest(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip(err)
	}
	oldLocal := time.Local
	defer func() { time.Local = oldLocal }()
	time.Local = loc
	resetCDFMktimeState()
	defer resetCDFMktimeState()

	// cdf_time.c sets tm_isdst=0. For a July wall time, glibc mktime
	// therefore uses the nearby standard offset and returns 17:00 UTC.
	got, ok := cdfMktime(cdfCivil{
		year: 2021, month: 6, day: 1, hour: 12,
	})
	if !ok {
		t.Fatal("cdfMktime returned failure")
	}
	want := time.Date(2021, time.July, 1, 17, 0, 0, 0, time.UTC).Unix()
	if got != want {
		t.Fatalf("cdfMktime = %d (%s), want %d (%s)",
			got, time.Unix(got, 0).UTC(), want, time.Unix(want, 0).UTC())
	}
}

func TestFormatWindowsUsesCDFTimestampConversion(t *testing.T) {
	oldLocal := time.Local
	defer func() { time.Local = oldLocal }()
	time.Local = time.UTC
	resetCDFMktimeState()
	defer resetCDFMktimeState()

	const ticks = uint64(0x01A5E403C2D59C00)
	if got := formatTimeFlags(ticks, timeWindows); got != "Sun Apr 24 01:30:00 1977" {
		t.Fatalf("Windows date = %q", got)
	}
	if got := formatTimeFlags(^uint64(0), timeWindows); got != "Mon Jan  1 00:00:00 1601" {
		t.Fatalf("negative Windows date = %q", got)
	}
}

func TestFormatWindowsRejectsAsctimeYearOverflow(t *testing.T) {
	oldLocal := time.Local
	defer func() { time.Local = oldLocal }()
	time.Local = time.UTC
	resetCDFMktimeState()
	defer resetCDFMktimeState()

	days := int64(10000-1601)*365 + int64(cdfGetDays(10000)-1)
	ticks := uint64(days * 86400 * 10000000)
	if got := formatTimeFlags(ticks, timeWindows); got != "*Invalid time*" {
		t.Fatalf("Windows year overflow = %q", got)
	}
}

func TestFormatWindowsMatchesFILE541StateReplay(t *testing.T) {
	const epochTicks = int64(116444736000000000)
	ticks := func(year int, month time.Month, day, hour, minute int) uint64 {
		return uint64(epochTicks + time.Date(year, month, day, hour, minute, 0, 0, time.UTC).Unix()*10000000)
	}
	tests := []struct {
		zone       string
		primeA     uint64
		primeB     uint64
		target     uint64
		wantPrimeA string
		wantPrimeB string
		wantA      string
		wantB      string
	}{
		{
			zone:       "Europe/Moscow",
			primeA:     ticks(2014, time.October, 1, 12, 0),
			primeB:     ticks(2014, time.November, 1, 12, 0),
			target:     ticks(2014, time.October, 26, 1, 30),
			wantPrimeA: "Wed Oct  1 08:00:00 2014",
			wantPrimeB: "Sat Nov  1 09:00:00 2014",
			wantA:      "Sat Oct 25 21:30:00 2014",
			wantB:      "Sat Oct 25 22:30:00 2014",
		},
		{
			zone:       "Asia/Pyongyang",
			primeA:     ticks(2015, time.August, 1, 12, 0),
			primeB:     ticks(2015, time.September, 1, 12, 0),
			target:     ticks(2015, time.August, 14, 23, 45),
			wantPrimeA: "Sat Aug  1 03:00:00 2015",
			wantPrimeB: "Tue Sep  1 03:30:00 2015",
			wantA:      "Fri Aug 14 14:45:00 2015",
			wantB:      "Fri Aug 14 15:15:00 2015",
		},
		{
			zone:       "Pacific/Kwajalein",
			primeA:     ticks(1969, time.September, 25, 12, 0),
			primeB:     ticks(1969, time.October, 5, 12, 0),
			target:     ticks(1969, time.September, 30, 12, 0),
			wantPrimeA: "Thu Sep 25 01:00:00 1969",
			wantPrimeB: "Mon Oct  6 00:00:00 1969",
			wantA:      "Sun Aug 31 01:00:00 1969",
			wantB:      "Sun Aug 31 01:00:00 1969",
		},
	}

	oldLocal := time.Local
	defer func() { time.Local = oldLocal }()
	for _, tc := range tests {
		t.Run(tc.zone, func(t *testing.T) {
			loc, err := time.LoadLocation(tc.zone)
			if err != nil {
				t.Skip(err)
			}
			time.Local = loc
			resetCDFMktimeState()
			defer resetCDFMktimeState()

			if got := formatTimeFlags(tc.primeA, timeWindows); got != tc.wantPrimeA {
				t.Fatalf("prime A = %q, want %q", got, tc.wantPrimeA)
			}
			if got := formatTimeFlags(tc.target, timeWindows); got != tc.wantA {
				t.Fatalf("target after prime A = %q, want %q", got, tc.wantA)
			}
			if got := formatTimeFlags(tc.primeB, timeWindows); got != tc.wantPrimeB {
				t.Fatalf("prime B = %q, want %q", got, tc.wantPrimeB)
			}
			if got := formatTimeFlags(tc.target, timeWindows); got != tc.wantB {
				t.Fatalf("target after prime B = %q, want %q", got, tc.wantB)
			}
		})
	}
}
