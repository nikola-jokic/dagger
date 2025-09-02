package core

import (
	"github.com/vektah/gqlparser/v2/ast"
)

// SSHFSVolume is a persistent volume with a globally scoped identifier.
type SSHFSVolume struct {
	Endpoint   string `json:"endpoint"`
	PrivateKey Secret `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
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
