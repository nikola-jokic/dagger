package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/dagger/testctx"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type VolumeSuite struct{}

func TestVolume(t *testing.T) {
	testctx.New(t, Middleware()...).RunTests(VolumeSuite{})
}

func (VolumeSuite) TestSSHFSVolume(ctx context.Context, t *testctx.T) {
	c := connect(ctx, t)

	sshfs := c.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "git", "openssh", "openssl"})

	hostKeyGen := sshfs.
		WithExec([]string{
			"ssh-keygen", "-t", "rsa", "-b", "4096", "-f", "/root/.ssh/host_key", "-N", "",
		}).
		WithExec([]string{
			"ssh-keygen", "-t", "rsa", "-b", "4096", "-f", "/root/.ssh/id_rsa", "-N", "",
		}).
		WithExec([]string{
			"cp", "/root/.ssh/id_rsa.pub", "/root/.ssh/authorized_keys",
		})

	hostPubKey, err := hostKeyGen.File("/root/.ssh/host_key.pub").Contents(ctx)
	require.NoError(t, err)

	userPrivateKey, err := hostKeyGen.File("/root/.ssh/id_rsa").Contents(ctx)
	require.NoError(t, err)

	setupScript := c.Directory().
		WithNewFile("setup.sh", `#!/bin/sh

set -e -u -x

cd /root
mkdir repo
cd repo
echo test >> content.txt

chmod 0600 ~/.ssh/host_key
$(which sshd) -h ~/.ssh/host_key -p 2222

sleep infinity
`).
		File("setup.sh")

	key, err := ssh.ParseRawPrivateKey([]byte(userPrivateKey))
	require.NoError(t, err)

	sshAgent := agent.NewKeyring()
	err = sshAgent.Add(agent.AddedKey{
		PrivateKey: key,
	})
	require.NoError(t, err)

	tmp := t.TempDir()
	sock := filepath.Join(tmp, "agent.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	defer l.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Logf("accept: %s", err)
					panic(err)
				}
				break
			}

			t.Log("agent serving")

			err = agent.ServeAgent(sshAgent, c)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Logf("serve agent: %s", err)
				panic(err)
			}
		}
	}()

	sshPort := 2223
	sshSvc := hostKeyGen.
		WithMountedFile("/root/start.sh", setupScript).
		WithExposedPort(sshPort).
		WithDefaultArgs([]string{"sh", "/root/start.sh"}).
		AsService()

	sshHost, err := sshSvc.Hostname(ctx)
	require.NoError(t, err)

	sshfsEndpoint := fmt.Sprintf("root@%s:%d:/root/repo", sshHost, sshPort)

	privKeySecret := c.SetSecret("sshfs-private-key", string(userPrivateKey))
	hostKeySecret := c.SetSecret("sshfs-host-key", string(hostPubKey))

	sshfsVolume := c.SshfsVolume(sshfsEndpoint, privKeySecret, hostKeySecret)

	output, err := c.Container().
		From(alpineImage).
		WithVolumeMount("/mnt/repo", sshfsVolume).
		WithExec([]string{"cat", "/mnt/repo/content.txt"}).
		Stdout(ctx)
	require.NoError(t, err)
	require.Contains(t, output, "test")

}
