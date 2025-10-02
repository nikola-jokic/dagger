package core

import (
	"context"
	"fmt"
	"testing"

	"dagger.io/dagger"
	"github.com/dagger/dagger/internal/testutil"
	"github.com/dagger/testctx"
	"github.com/stretchr/testify/require"
)

type VolumeSuite struct{}

func TestVolume(t *testing.T) {
	testctx.New(t, Middleware()...).RunTests(VolumeSuite{})
}

func (VolumeSuite) TestSSHFSVolume(ctx context.Context, t *testctx.T) {
	c := connect(ctx, t)

	engine := devEngineContainer(c, engineWithConfig(ctx, t))
	engineSvc, err := c.Host().Tunnel(devEngineContainerAsService(engine)).Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { engineSvc.Stop(ctx) })

	endpoint, err := engineSvc.Endpoint(ctx, dagger.ServiceEndpointOpts{Scheme: "tcp"})
	require.NoError(t, err)

	c2, err := dagger.Connect(ctx, dagger.WithRunnerHost(endpoint), dagger.WithLogOutput(testutil.NewTWriter(t)))
	require.NoError(t, err)
	t.Cleanup(func() { c2.Close() })

	// Set up SSH server container
	sshServer := c2.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "openssh", "openssh-sftp-server"})

	// Generate SSH keys
	sshServer = sshServer.
		WithExec([]string{
			"ssh-keygen", "-t", "rsa", "-b", "4096", "-f", "/root/.ssh/host_key", "-N", "",
		}).
		WithExec([]string{
			"ssh-keygen", "-t", "rsa", "-b", "4096", "-f", "/root/.ssh/id_rsa", "-N", "",
		}).
		WithExec([]string{
			"cp", "/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys",
		})

	// Get the keys for the client
	userPrivateKey, err := sshServer.File("/root/.ssh/id_rsa").Contents(ctx)
	require.NoError(t, err)

	userPubKey, err := sshServer.File("/root/.ssh/id_rsa.pub").Contents(ctx)
	require.NoError(t, err)

	// Create some test files in the SSH server
	sshServer = sshServer.
		WithNewFile("/root/test.txt", "Hello from SSH server!").
		WithNewFile("/root/data.json", `{"test": "data"}`)

	// Start SSH server
	sshPort := 2222
	sshSvc := sshServer.
		WithExposedPort(sshPort).
		WithExec([]string{
			"/usr/sbin/sshd",
			"-h", "/root/.ssh/host_key",
			"-p", fmt.Sprintf("%d", sshPort),
		}).
		AsService()

	// Start the SSH service
	sshSvcStarted, err := sshSvc.Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { sshSvcStarted.Stop(ctx) })

	sshHost, err := sshSvcStarted.Hostname(ctx)
	require.NoError(t, err)

	// Create SSHFS volume
	sshEndpoint := fmt.Sprintf("root@%s:%d/root", sshHost, sshPort)
	sshfsVol := c2.SshfsVolume(
		sshEndpoint,
		c2.SetSecret("ssh-private-key", userPrivateKey),
		c2.SetSecret("ssh-public-key", userPubKey),
	)

	// Test that we can access files from the SSHFS volume by mounting it into a container
	testContainer := c2.Container().
		From(alpineImage).
		WithVolumeMount("/mnt/sshfs", sshfsVol)

	// Read files from the mounted volume
	testFile, err := testContainer.File("/mnt/sshfs/test.txt").Contents(ctx)
	require.NoError(t, err)
	require.Equal(t, "Hello from SSH server!", testFile)

	dataFile, err := testContainer.File("/mnt/sshfs/data.json").Contents(ctx)
	require.NoError(t, err)
	require.Equal(t, `{"test": "data"}`, dataFile)

	// Test directory listing
	entries, err := testContainer.Directory("/mnt/sshfs").Entries(ctx)
	require.NoError(t, err)
	require.Contains(t, entries, "test.txt")
	require.Contains(t, entries, "data.json")
}
