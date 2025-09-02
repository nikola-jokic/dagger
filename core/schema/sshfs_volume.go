package schema

import (
	"context"

	"github.com/dagger/dagger/core"
	"github.com/dagger/dagger/dagql"
)

type sshfsVolumeSchema struct{}

var _ SchemaResolvers = &sshfsVolumeSchema{}

func (s *sshfsVolumeSchema) Name() string {
	return "sshfsVolume"
}

func (s *sshfsVolumeSchema) Install(srv *dagql.Server) {
	dagql.Fields[*core.Query]{
		dagql.NodeFunc("sshfsVolume", s.sshfsVolume).
			Doc("Constructs a sshfsVolume volume for a given sshfsVolume key.").
			Args(
				dagql.Arg("endpoint").Doc("The sshfs endpoint, in the form user@host:/path/to/dir"),
				dagql.Arg("privateKey").Doc("The private key to use for authentication.").Sensitive(),
				dagql.Arg("publicKey").Doc("The public key to use for authentication."),
			),
	}.Install(srv)

	dagql.Fields[*core.SSHFSVolume]{}.Install(srv)
}

func (s *sshfsVolumeSchema) Dependencies() []SchemaResolvers {
	return nil
}

type sshfsVolumeArgs struct {
	Endpoint   string
	PrivateKey core.Secret
	PublicKey  string
}

func (s *sshfsVolumeSchema) sshfsVolume(ctx context.Context, parent dagql.ObjectResult[*core.Query], args sshfsVolumeArgs) (dagql.Result[*core.SSHFSVolume], error) {
	panic("not implemented")
}
