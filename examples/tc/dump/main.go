// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os/signal"
	"os"
	"github.com/habibiefaried/goebpf"
)

const (
	SO_BINDTODEVICE = 25
)

var iface = flag.String("iface", "enp0s8", "Interface to bind XDP program to")
var elf = flag.String("elf", "ebpf_prog/dump.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "tc_dump", "Name of XDP program (function name)")

func main() {
	flag.Parse()
	if *iface == "" {
		fatalError("Interface (-iface) is required.")
	}

	// Create eBPF system / load .ELF file compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	tc := bpf.GetProgramByName(*programName)
	if tc == nil {
		fatalError("Program '%s' not found.", *programName)
	}

	err = tc.Load()
	if err != nil {
		fatalError("tc.Load(): %v", err)
	}

	err = tc.Attach(goebpf.TCattachparams{*iface, *elf})
	if err != nil {
		fatalError("tc.Attach(): %v", err)
	}
	defer tc.Detach()

	// Find special "PERF_EVENT" eBPF map
	perfmap := bpf.GetMapByName("perfmap")
	if perfmap == nil {
		fatalError("eBPF map 'perfmap' not found")
	}

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Start listening to Perf Events
	perf, _ := goebpf.NewPerfEvents(perfmap)
	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		fatalError("perf.StartForAllProcessesAndCPUs(): %v", err)
	}

	go func() {
		for {
			if eventData, ok := <-perfEvents; ok {
				fmt.Println(eventData)
			} else {
				break
			}
		}
	}()
	// Wait until Ctrl+C pressed
	<-ctrlC

	// Stop perf events and print summary
	perf.Stop()
	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", perf.EventsReceived)
	fmt.Printf("\t%d Event(s) lost (e.g. small buffer, delays in processing)\n", perf.EventsLost)
	fmt.Println("\nDetaching program and exit...")
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}
