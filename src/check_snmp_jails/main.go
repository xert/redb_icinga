// Copyright 2012-2014 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This program demonstrates BulkWalk.
package main

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/olorin/nagiosplugin"
	"github.com/soniah/gosnmp"
)

type nagiosPerf struct {
	Name string
	Unit string
}

var perfData = map[int]nagiosPerf{
	10: nagiosPerf{Name: "InOctets", Unit: "c"},
	11: nagiosPerf{Name: "InPackets", Unit: "c"},
	12: nagiosPerf{Name: "OutOctets", Unit: "c"},
	13: nagiosPerf{Name: "OutPackets", Unit: "c"},

	20: nagiosPerf{Name: "Processes", Unit: ""},
	21: nagiosPerf{Name: "Threads", Unit: ""},
	25: nagiosPerf{Name: "CpuTime", Unit: "s"},

	30: nagiosPerf{Name: "DiskSpace", Unit: "b"},
	31: nagiosPerf{Name: "DiskFiles", Unit: ""},
}

const oidBase = ".1.3.6.1.4.1.12325.1.1111"
const oidJails = ".2.1"
const oidJailNames = ".1"

var opts struct {
	Host      string        `short:"H" long:"hostname" description:"host name" required:"true"`
	Port      uint16        `short:"p" long:"port" description:"port number" default:"1161"`
	Jail      string        `short:"j" long:"jail" description:"jail name" required:"true"`
	Community string        `short:"C" long:"community" description:"SNMP community string" default:"public"`
	Timeout   time.Duration `short:"t" long:"timeout" description:"connection time out" default:"10s"`
	Warning   int           `short:"w" long:"warning" description:"Warning disk usage in GB"`
	Critical  int           `short:"c" long:"critical" description:"Warning disk usage in GB"`
	Verbose   []bool        `short:"v" long:"verbose" description:"verbose output for debugging"`
}

func debug(f string, a ...interface{}) {
	if len(opts.Verbose) > 0 {
		fmt.Printf(f+"\n", a...)
	}
}

func main() {
	if _, err := flags.Parse(&opts); err != nil {
		os.Exit(int(nagiosplugin.UNKNOWN))
	}
	// Initialize the check - this will return an UNKNOWN result
	// until more results are added.
	check := nagiosplugin.NewCheck()
	// If we exit early or panic() we'll still output a result.
	defer check.Finish()

	debug("Options: %+v", opts)

	if opts.Warning > opts.Critical {
		check.Exitf(nagiosplugin.UNKNOWN, "Warning %d can't be bigger than critical %d", opts.Warning, opts.Critical)
	}

	snmp := &gosnmp.GoSNMP{
		Target:    opts.Host,
		Port:      opts.Port,
		Community: opts.Community,
		Version:   gosnmp.Version2c,
		Timeout:   opts.Timeout,
		Retries:   3,
	}

	err := snmp.Connect()
	if err != nil {
		check.Exitf(nagiosplugin.UNKNOWN, "Connect err: %v", err)
	}
	defer snmp.Conn.Close()
	debug("Connected to %s:%d", opts.Host, opts.Port)

	bulk, err := snmp.BulkWalkAll(oidBase)
	if err != nil {
		check.Exitf(nagiosplugin.UNKNOWN, "Walk error: %v", err)
	}
	debug("Walk returned %d items", len(bulk))

	jailIndex := -1
	data := make(map[string]gosnmp.SnmpPDU)
	for _, pdu := range bulk {
		if jailIndex == -1 { // JailIndex still not found
			s := strings.Split(pdu.Name, oidBase+oidJails+oidJailNames+".")
			if len(s) == 2 && opts.Jail == string(pdu.Value.([]byte)) {
				jailIndex, err = strconv.Atoi(s[1])
				if err != nil {
					check.Unknownf("Can't determine jail index: %s", err.Error())
				}
				debug("Jail %s has index %d", opts.Jail, jailIndex)
			}
		}

		// store data indexed by oid
		data[pdu.Name] = pdu
	}

	if jailIndex == -1 {
		check.Criticalf("Jail %s not found", opts.Jail)
	}

	// Sort the keys for consistent output
	var keys []int
	for k := range perfData {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	for _, i := range keys {
		index := fmt.Sprintf("%s%s.%d.%d", oidBase, oidJails, i, jailIndex)
		value := float64(gosnmp.ToBigInt(data[index].Value).Int64())

		min := math.NaN()
		max := math.NaN()
		warn := math.NaN()
		crit := math.NaN()

		if perfData[i].Name == "DiskSpace" {
			gb := float64(1024 * 1024 * 1024)
			size := int(value / gb)
			result := nagiosplugin.OK

			if opts.Warning > 0 {
				warn = float64(opts.Warning) * gb
				if size > opts.Warning {
					result = nagiosplugin.WARNING
				}
			}

			if opts.Critical > 0 {
				crit = float64(opts.Critical) * gb
				if size > opts.Critical {
					result = nagiosplugin.CRITICAL
				}
			}

			check.AddResultf(result, "Jail %s is using %d / %d GB disk space (%d%%)", opts.Jail, size, opts.Warning, size*100/opts.Warning)
		}

		if perfData[i].Name == "CpuTime" {
			value = value / 100
		}

		check.AddPerfDatum(perfData[i].Name, perfData[i].Unit, value, min, max, warn, crit)

	}

}
