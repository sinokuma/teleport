package teleagent

import (
	"sync"

	"github.com/gravitational/trace"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Lazy is an Agent instance which is lazily initialized
// via a call to an AgentGetter.  Helpful for dealing with APIs
// which require, but may not actually use, an agent.
type Lazy struct {
	get  AgentGetter
	once sync.Once
	ref  Agent
	err  error
}

// NewLazy wraps an AgentGetter in an Agent interface which lazily
// initializes the agent on first method invocation.
func NewLazy(get AgentGetter) *Lazy {
	return &Lazy{
		get: get,
	}
}

// agent gets the lazily initialized agent
func (l *Lazy) agent() (Agent, error) {
	l.once.Do(func() {
		l.ref, l.err = l.get()
	})
	return l.ref, l.err
}

// List returns the identities known to the agent.
func (l *Lazy) List() ([]*agent.Key, error) {
	a, err := l.agent()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return a.List()
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (l *Lazy) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a, err := l.agent()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Sign(key, data)
}

// Add adds a private key to the agent.
func (l *Lazy) Add(key agent.AddedKey) error {
	a, err := l.agent()
	if err != nil {
		return trace.Wrap(err)
	}
	return a.Add(key)
}

// Remove removes all identities with the given public key.
func (l *Lazy) Remove(key ssh.PublicKey) error {
	a, err := l.agent()
	if err != nil {
		return trace.Wrap(err)
	}
	return a.Remove(key)
}

// RemoveAll removes all identities.
func (l *Lazy) RemoveAll() error {
	a, err := l.agent()
	if err != nil {
		return trace.Wrap(err)
	}
	return a.RemoveAll()
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (l *Lazy) Lock(passphrase []byte) error {
	a, err := l.agent()
	if err != nil {
		return trace.Wrap(err)
	}
	return a.Lock(passphrase)
}

// Unlock undoes the effect of Lock
func (l *Lazy) Unlock(passphrase []byte) error {
	a, err := l.agent()
	if err != nil {
		return trace.Wrap(err)
	}
	return a.Unlock(passphrase)
}

// Signers returns signers for all the known keys.
func (l *Lazy) Signers() ([]ssh.Signer, error) {
	a, err := l.agent()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return a.Signers()
}

func (l *Lazy) Close() error {
	needsClose := true
	l.once.Do(func() {
		// Setup was never run, put outselves into an error state
		// so that any future calls to agent methods fail.
		needsClose = false
		l.err = trace.NotFound("agent closed")
	})
	if !needsClose {
		return nil
	}
	// setup has been run, perform a normal close operation.
	a, err := l.agent()
	if err != nil {
		return trace.Wrap(err)
	}
	return a.Close()
}
