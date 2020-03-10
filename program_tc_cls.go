package goebpf

//#include "bpf_helpers.h"
import "C"

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

var debugCommand bool = true

type tcCLSProgram struct {
	BaseProgram
	Iface   string
	ElfFile string
	sockFd  int
}

type TCattachparams struct {
	Iface   string
	ElfFile string
}

func runCommand(s string) {
	c := strings.Split(s, " ")
	cmd := exec.Command(c[0], c[1:]...)

	if debugCommand {
		fmt.Println("Run the program ", c)
	}

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
		return
	}

	if debugCommand {
		fmt.Printf("Output: %v\n", out.String())
	}
}

func newTCCls(name, license string, bytecode []byte) Program {
	return &tcCLSProgram{
		BaseProgram: BaseProgram{
			name:        name,
			license:     license,
			bytecode:    bytecode,
			programType: ProgramTypeSchedCls,
		},
	}
}

func (p *tcCLSProgram) Attach(data interface{}) error {
	params, ok := data.(TCattachparams)
	if !ok {
		return fmt.Errorf("TCattachparams expected, got %T", data)
	}

	p.Iface = params.Iface
	p.ElfFile = params.ElfFile

	runCommand("tc qdisc add dev " + p.Iface + " clsact")
	//runCommand("tc filter add dev " + p.Iface + " bpf da obj " + p.ElfFile)
	runCommand("tc filter add dev "+p.Iface+" ingress bpf da obj "+p.ElfFile+" sec classifier")
	runCommand("tc filter add dev "+p.Iface+" egress bpf da obj "+p.ElfFile+" sec classifier")
	runCommand("tc filter show dev " + p.Iface)
	return nil
}

func (p *tcCLSProgram) Detach() error {
	runCommand("tc qdisc del dev " + p.Iface)
	runCommand("tc filter del dev " + p.Iface + " clsact")
	return nil
}
