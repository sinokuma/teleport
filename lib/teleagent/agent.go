package teleagent

import (
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/agent"
)

// Agent extends the agent.Agent interface.
// APIs which accept this interface promise to
// call `Close()` when they are done using the
// supplied agent.
type Agent interface {
	agent.Agent
	io.Closer
}

// wrapper wraps an agent.Agent in the extended
// Agent interface.
type wrapper struct {
	agent.Agent
}

func (w wrapper) Close() error { return nil }

// WrapAgent wraps an instance of the standard agent.Agent interface
// in the extended Agent interface.  Note that calling Close on the
// resulting Agent is a NOP, even if the underyling type of the
// supplied agent.Agent instance has a Close method.  This means that
// WrapAgent can also be called on an instance of the extended Agent
// interface in order to protect its Close method from being called.
func WrapAgent(std agent.Agent) Agent {
	return wrapper{std}
}

// AgentGetter is a function used to get an agent instance.
type AgentGetter func() (Agent, error)

// AgentServer is implementation of SSH agent server
type AgentServer struct {
	getAgent AgentGetter
	listener net.Listener
	path     string
}

// NewServer returns new instance of agent server
func NewServer(getter AgentGetter) *AgentServer {
	return &AgentServer{getAgent: getter}
}

// startServe starts serving agent protocol against conn
func (a *AgentServer) startServe(conn net.Conn) error {
	instance, err := a.getAgent()
	if err != nil {
		return trace.Wrap(err)
	}
	go func() {
		defer instance.Close()
		if err := agent.ServeAgent(instance, conn); err != nil {
			if err != io.EOF {
				log.Error(err.Error())
			}
		}
	}()
	return nil
}

// ListenUnixSocket starts listening and serving agent assuming that
func (a *AgentServer) ListenUnixSocket(path string, uid, gid int, mode os.FileMode) error {
	l, err := net.Listen("unix", path)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		l.Close()
		return trace.ConvertSystemError(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return trace.ConvertSystemError(err)
	}
	a.listener = l
	a.path = path
	return nil
}

// Serve starts serving on the listener, assumes that Listen was called before
func (a *AgentServer) Serve() error {
	if a.listener == nil {
		return trace.BadParameter("Serve needs a Listen call first")
	}
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			neterr, ok := err.(net.Error)
			if !ok {
				return trace.Wrap(err, "unknown error")
			}
			if !neterr.Temporary() {
				if !strings.Contains(neterr.Error(), "use of closed network connection") {
					log.Errorf("got permanent error: %v", err)
				}
				return err
			}
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 1 * time.Second; tempDelay > max {
				tempDelay = max
			}
			log.Errorf("got temp error: %v, will sleep %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
		if err := a.startServe(conn); err != nil {
			log.Errorf("Failed to start serving agent: %v", err)
			return trace.Wrap(err)
		}
	}
}

// ListenAndServe is similar http.ListenAndServe
func (a *AgentServer) ListenAndServe(addr utils.NetAddr) error {
	l, err := net.Listen(addr.AddrNetwork, addr.Addr)
	if err != nil {
		return trace.Wrap(err)
	}
	a.listener = l
	return a.Serve()
}

// Close closes listener and stops serving agent
func (a *AgentServer) Close() error {
	var errors []error
	if a.listener != nil {
		log.Debugf("AgentServer(%v) is closing", a.listener.Addr())
		if err := a.listener.Close(); err != nil {
			errors = append(errors, trace.ConvertSystemError(err))
		}
	}
	if a.path != "" {
		if err := os.Remove(a.path); err != nil {
			errors = append(errors, trace.ConvertSystemError(err))
		}
	}
	return trace.NewAggregate(errors...)
}
