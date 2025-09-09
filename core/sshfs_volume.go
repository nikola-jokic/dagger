package core

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/dagger/dagger/dagql"
	"github.com/moby/buildkit/solver/pb"
	"github.com/vektah/gqlparser/v2/ast"
	"golang.org/x/crypto/ssh/agent"
)

// SSHFSVolume is a persistent volume with a globally scoped identifier.
type SSHFSVolume struct {
	LLB *pb.Definition

	Endpoint  string
	Backend   *SSHBackend
	SSHSocket dagql.ObjectResult[*Socket]
}

func (*SSHFSVolume) Type() *ast.Type {
	return &ast.Type{
		NamedType: "SSHFSVolume",
		NonNull:   true,
	}
}

func (*SSHFSVolume) TypeDescription() string {
	return "A directory whose contents persist across runs."
}

type SSHBackend struct {
	PrivateKey string
	PublicKey  string
	SocketPath string

	listener net.Listener
}

func (b *SSHBackend) Start() error {
	sshAgent := agent.NewKeyring()
	if err := sshAgent.Add(agent.AddedKey{
		PrivateKey: b.PrivateKey,
	}); err != nil {
		return fmt.Errorf("failed to add private key to ssh agent: %w", err)
	}

	l, err := net.Listen("unix", b.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create SSH agent socket: %w", err)
	}
	b.listener = l

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					panic(err)
				}
				break
			}

			err = agent.ServeAgent(sshAgent, c)
			if err != nil && !errors.Is(err, io.EOF) {
				panic(err)
			}
		}
	}()

	return nil
}

func (b *SSHBackend) Stop() error {
	if b.listener != nil {
		return b.listener.Close()
	}
	return nil
}
