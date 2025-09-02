package schema

import (
	"context"
	"errors"

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
				dagql.Arg("key").Doc(`A string identifier to target this sshfsVolume volume (e.g., "modules-sshfsVolume").`),
			),
	}.Install(srv)

	dagql.Fields[*core.SSHFSVolume]{}.Install(srv)
}

func (s *sshfsVolumeSchema) Dependencies() []SchemaResolvers {
	return nil
}

type sshfsVolumeArgs struct {
	Key       string
	Namespace string `internal:"true" default:""`
}

func (s *sshfsVolumeSchema) sshfsVolume(ctx context.Context, parent dagql.ObjectResult[*core.Query], args sshfsVolumeArgs) (dagql.Result[*core.SSHFSVolume], error) {
	var inst dagql.Result[*core.SSHFSVolume]

	srv, err := core.CurrentDagqlServer(ctx)
	if err != nil {
		return inst, err
	}

	if args.Namespace != "" {
		return dagql.NewResultForCurrentID(ctx, core.NewSSHFSVolume(args.Namespace+":"+args.Key))
	}

	m, err := parent.Self().CurrentModule(ctx)
	if err != nil && !errors.Is(err, core.ErrNoCurrentModule) {
		return inst, err
	}
	namespaceKey := namespaceFromModule(m)
	err = srv.Select(ctx, srv.Root(), &inst, dagql.Selector{
		Field: "sshfsVolume",
		Args: []dagql.NamedInput{
			{
				Name:  "key",
				Value: dagql.NewString(args.Key),
			},
			{
				Name:  "namespace",
				Value: dagql.NewString(namespaceKey),
			},
		},
	})
	if err != nil {
		return inst, err
	}

	return inst, nil
}
