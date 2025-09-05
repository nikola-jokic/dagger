package core

import (
	"github.com/dagger/dagger/dagql"
	"github.com/moby/buildkit/solver/pb"
	"github.com/vektah/gqlparser/v2/ast"
)

// SSHFSVolume is a persistent volume with a globally scoped identifier.
type SSHFSVolume struct {
	LLB *pb.Definition

	Endpoint  string
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
