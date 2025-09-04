package schema

import (
	"context"
	"fmt"

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
				dagql.Arg("privateKey").Doc("Secret used to populate the private key").Sensitive(),
				dagql.Arg("publicKey").Doc("The public key to use for authentication."),
			),
	}.Install(srv)

	dagql.Fields[*core.SSHFSVolume]{}.Install(srv)
}

func (s *sshfsVolumeSchema) Dependencies() []SchemaResolvers {
	return nil
}

type sshfsVolumeArgs struct {
	Endpoint   string        `name:"endpoint"`
	PrivateKey core.SecretID `name:"privateKey"`
	PublicKey  string        `name:"publicKey"`
}

func (s *sshfsVolumeSchema) sshfsVolume(ctx context.Context, parent dagql.ObjectResult[*core.Query], args sshfsVolumeArgs) (dagql.Result[*core.SSHFSVolume], error) {
	srv, err := core.CurrentDagqlServer(ctx)
	if err != nil {
		return dagql.Result[*core.SSHFSVolume]{}, fmt.Errorf("failed to get dagql server: %w", err)
	}

	privateKey, err := args.PrivateKey.Load(ctx, srv)
	if err != nil {
		return dagql.Result[*core.SSHFSVolume]{}, fmt.Errorf("failed to load private key from secret ID: %w", err)
	}

	return dagql.NewResultForCurrentID(ctx, &core.SSHFSVolume{
		Endpoint:   args.Endpoint,
		PrivateKey: *privateKey.Self(),
		PublicKey:  args.PublicKey,
	})
}
