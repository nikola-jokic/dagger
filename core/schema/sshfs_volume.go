package schema

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dagger/dagger/core"
	"github.com/dagger/dagger/dagql"
	"github.com/dagger/dagger/engine"
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

func (s *sshfsVolumeSchema) sshfsVolume(ctx context.Context, parent dagql.ObjectResult[*core.Query], args sshfsVolumeArgs) (inst dagql.Result[*core.SSHFSVolume], err error) {
	srv, err := core.CurrentDagqlServer(ctx) // get server
	if err != nil {
		return inst, err
	}

	query, err := core.CurrentQuery(ctx) // get current query
	if err != nil {
		return inst, err
	}

	secrets, err := query.Secrets(ctx) // secret store
	if err != nil {
		return inst, err
	}

	privateKey, err := secrets.GetSecretPlaintext(ctx, args.PrivateKey.ID().Digest())
	if err != nil {
		return inst, fmt.Errorf("failed to get private key secret: %w", err)
	}

	socketStore, err := query.Sockets(ctx) // socket store
	if err != nil {
		return inst, err
	}

	clientMetadata, err := engine.ClientMetadataFromContext(ctx) // needed for Add*Socket
	if err != nil {
		return inst, err
	}

	tmpDir, err := os.MkdirTemp("", "sshfs-*")
	if err != nil {
		return inst, fmt.Errorf("failed to create temp dir for sshfs socket: %w", err)
	}
	socketPath := filepath.Join(tmpDir, "ssh-agent.sock")

	// compute an accessor for the socket. For host path use:
	accessor, err := core.GetClientResourceAccessor(ctx, query, socketPath)
	if err != nil {
		return inst, err
	}

	// compute digest (this becomes the socket ID)
	dgst := dagql.HashFrom(accessor)

	// create the Socket object
	sock := &core.Socket{IDDigest: dgst}

	// create an ObjectResult for the socket (so you can embed it in other objects)
	sockInst, err := dagql.NewObjectResultForCurrentID(ctx, srv, sock)
	if err != nil {
		return inst, err
	}

	// ensure the returned ID has the digest in it (same pattern used in host.socket)
	sockInst = sockInst.WithObjectDigest(dgst)

	// register socket in the store so MountSocket/ForwardAgent can find it.
	// For a unix socket on the client host:
	if err := socketStore.AddUnixSocket(sock, clientMetadata.ClientID, socketPath); err != nil {
		return inst, fmt.Errorf("failed to add unix socket to store: %w", err)
	}

	backend := &core.SSHBackend{
		PrivateKey: string(privateKey),
		PublicKey:  args.PublicKey,
		SocketPath: socketPath,
	}

	if err := backend.Start(); err != nil {
		return inst, fmt.Errorf("failed to start ssh backend: %w", err)
	}

	// Now attach sockInst to your SSHFSVolume being returned:
	return dagql.NewResultForCurrentID(ctx, &core.SSHFSVolume{
		Endpoint:  args.Endpoint,
		SSHSocket: sockInst, // <-- ObjectResult[*core.Socket]
		Backend:   backend,
		// ...other fields...
	})
}
