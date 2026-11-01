package libmagic

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// cdfCivil is the struct tm assembled by FILE5_41 cdf_time.c before it calls
// mktime. Month is zero based, as in struct tm.
type cdfCivil struct {
	year   int
	month  int
	day    int
	hour   int
	minute int
	second int
}

// glibc keeps localtime_offset in static storage inside mktime. The lock is
// deliberately around the whole conversion so concurrent CDF queries observe
// one ordered state, rather than racing on that process-global heuristic.
var cdfMktimeState struct {
	sync.Mutex
	offset int64
}

func cdfLeap(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

func cdfGetDays(year int) int {
	days := 0
	for y := 1601; y < year; y++ {
		days += 365
		if cdfLeap(y) {
			days++
		}
	}
	return days
}

func cdfGetDay(year, days int) int {
	monthDays := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	for month, daysInMonth := range monthDays {
		if month == 1 && cdfLeap(year) {
			daysInMonth++
		}
		if days < daysInMonth {
			return days
		}
		days -= daysInMonth
	}
	return days
}

func cdfGetMonth(year, days int) int {
	monthDays := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	for month, daysInMonth := range monthDays {
		days -= daysInMonth
		if month == 1 && cdfLeap(year) {
			days--
		}
		if days <= 0 {
			return month
		}
	}
	return len(monthDays)
}

func cdfCivilFromTimestamp(ticks int64) cdfCivil {
	t := ticks / 10000000
	second := int(t % 60)
	t /= 60
	minute := int(t % 60)
	t /= 60
	hour := int(t % 24)
	t /= 24

	year := 1601 + int(t/365)
	t -= int64(cdfGetDays(year) - 1)
	return cdfCivil{
		year:   year,
		month:  cdfGetMonth(year, int(t)),
		day:    cdfGetDay(year, int(t)),
		hour:   hour,
		minute: minute,
		second: second,
	}
}

func cdfCivilUnix(c cdfCivil) int64 {
	return time.Date(c.year, time.Month(c.month+1), c.day,
		c.hour, c.minute, c.second, 0, time.UTC).Unix()
}

func cdfCivilFromLocal(t time.Time) cdfCivil {
	return cdfCivil{
		year:   t.Year(),
		month:  int(t.Month()) - 1,
		day:    t.Day(),
		hour:   t.Hour(),
		minute: t.Minute(),
		second: t.Second(),
	}
}

// cdfMktime is the relevant FILE5_41/glibc __mktime_internal path. It uses
// the previous offset as the first probe, iterates on the wall-clock error,
// and handles a requested standard-time result that lands in DST by probing
// both sides of the transition.
func cdfMktime(c cdfCivil) (int64, bool) {
	naive := cdfCivilUnix(c)

	cdfMktimeState.Lock()
	defer cdfMktimeState.Unlock()

	off := cdfMktimeState.offset
	t := naive + off
	t1, t2 := t, t
	remaining := 6
	var local time.Time

	for {
		local = time.Unix(t, 0).In(time.Local)
		delta := naive - cdfCivilUnix(cdfCivilFromLocal(local))
		if delta == 0 {
			break
		}
		if t == t1 && t != t2 && local.IsDST() {
			break
		}
		remaining--
		if remaining == 0 {
			return 0, false
		}
		t1, t2 = t2, t
		t += delta
	}

	if local.IsDST() {
		const stride = int64(601200)
		const maxDelta = int64(536454000/2) + stride
		for delta := stride; delta < maxDelta; delta += stride {
			for _, direction := range []int64{-1, 1} {
				probe := t + delta*direction
				probeLocal := time.Unix(probe, 0).In(time.Local)
				if probeLocal.IsDST() {
					continue
				}
				adjusted := probe + naive -
					cdfCivilUnix(cdfCivilFromLocal(probeLocal))
				t = adjusted
				local = time.Unix(t, 0).In(time.Local)
				goto offsetFound
			}
		}
		return 0, false
	}

offsetFound:
	cdfMktimeState.offset = t - naive
	return t, true
}

// FILE5_41 cdf_time.c intentionally uses an approximate year and its own
// day/month conversion. Standard Windows FILETIME conversion differs at
// month boundaries; preserve this version's output.
func cdfTime(ticks int64) string {
	seconds := ticks / 10000000
	sec, min := seconds%60, seconds/60%60
	if ticks < 1000000000000000 {
		var out strings.Builder
		days, hours := seconds/86400, seconds/3600%24
		if days != 0 {
			fmt.Fprintf(&out, "%dd+", days)
		}
		if days != 0 || hours != 0 {
			fmt.Fprintf(&out, "%02d:", hours)
		}
		fmt.Fprintf(&out, "%02d:%02d", min, sec)
		return out.String()
	}

	civil := cdfCivilFromTimestamp(ticks)
	seconds, ok := cdfMktime(civil)
	if !ok {
		return "*Invalid time*"
	}
	return time.Unix(seconds, 0).In(time.Local).Format("Mon Jan _2 15:04:05 2006")
}
