package goebpf

//#include "bpf_helpers.h"
import "C"

type tcACTProgram struct {
	BaseProgram
	sockFd int
}

func newTCAct(name, license string, bytecode []byte) Program {
	return &tcACTProgram{
		BaseProgram: BaseProgram{
			name:        name,
			license:     license,
			bytecode:    bytecode,
			programType: ProgramTypeSchedAct,
		},
	}
}

func (p *tcACTProgram) Attach(data interface{}) error {
	// tc qdisc add dev enp0s8 clsact
	// tc filter add dev enp0s8 bpf da obj tc.o
	// tc filter show dev enp0s8
	return nil
}

func (p *tcACTProgram) Detach() error {
	// tc filter del dev enp0s8
	// tc qdisc del dev enp0s8 clsact
	return nil
}
