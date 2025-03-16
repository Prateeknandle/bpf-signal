package agent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// Event struct - conatins kill attempt event
type Event struct {
	SrcPid    uint32
	TargetPid uint32
	Sig       int32
	Blocked   int32
}

// Agent struct - ebpf objects and other utilities
type Agent struct {
	objects struct {
		Prog        *ebpf.Program `ebpf:"task_kill"`
		AgentPidMap *ebpf.Map     `ebpf:"agent_pid_map"`
		Events      *ebpf.Map     `ebpf:"events"`
	}
	reader  *perf.Reader
	lsmLink link.Link
}

func RunAgent() error {
	agent := &Agent{}
	defer agent.cleanup()

	agentPid := uint32(os.Getpid())
	log.Printf("Agent running with PID: %d", agentPid)

	// loads ebpf program
	if err := agent.loadEBPFProgram(); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	// store agent PID in ebpf map
	if err := agent.storeAgentPID(agentPid); err != nil {
		return fmt.Errorf("failed to store agent PID: %w", err)
	}

	// attach LSM hook
	if err := agent.attachLSMHook(); err != nil {
		return fmt.Errorf("failed to attach LSM hook: %w", err)
	}

	// perf event reader
	if err := agent.startPerfEventReader(); err != nil {
		return fmt.Errorf("failed to start perf event reader: %w", err)
	}

	select {}
}

func (a *Agent) loadEBPFProgram() error {
	spec, err := ebpf.LoadCollectionSpec("agent.o")
	if err != nil {
		return fmt.Errorf("error loading ebpf spec: %w", err)
	}

	if err := spec.LoadAndAssign(&a.objects, nil); err != nil {
		return fmt.Errorf("error loading ebpf program: %w", err)
	}

	return nil
}

func (a *Agent) storeAgentPID(pid uint32) error {
	key := uint32(0)
	if err := a.objects.AgentPidMap.Put(&key, &pid); err != nil {
		return fmt.Errorf("error storing agent PID in map: %w", err)
	}
	return nil
}

func (a *Agent) attachLSMHook() error {
	lsm, err := link.AttachLSM(link.LSMOptions{Program: a.objects.Prog})
	if err != nil {
		return fmt.Errorf("error attaching LSM hook: %w", err)
	}
	a.lsmLink = lsm
	return nil
}

func (a *Agent) startPerfEventReader() error {
	reader, err := perf.NewReader(a.objects.Events, 4096)
	if err != nil {
		return fmt.Errorf("error creating perf reader: %w", err)
	}
	a.reader = reader

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if err == perf.ErrClosed {
					log.Println("Perf buffer closed, exiting reader")
					return
				}
				log.Printf("Error reading from perf buffer: %v", err)
				continue
			}

			var event Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Failed to decode event: %v", err)
				continue
			}

			if event.Blocked == 1 {
				fmt.Printf("Kill attempt targeting agent detected: source PID %d attempting to kill agent PID %d with signal %d\n",
					event.SrcPid, event.TargetPid, event.Sig)
				fmt.Println("Kill attempt blocked successfully")
			} else {
				fmt.Printf("Kill attempt detected: source PID %d attempting to kill target PID %d with signal %d\n",
					event.SrcPid, event.TargetPid, event.Sig)
			}
		}
	}()

	return nil
}

func (a *Agent) cleanup() {
	if a.reader != nil {
		a.reader.Close()
	}
	if a.lsmLink != nil {
		a.lsmLink.Close()
	}
	if a.objects.Prog != nil {
		a.objects.Prog.Close()
	}
	if a.objects.AgentPidMap != nil {
		a.objects.AgentPidMap.Close()
	}
	if a.objects.Events != nil {
		a.objects.Events.Close()
	}
}
