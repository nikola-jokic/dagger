package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/dagger/dagger/core"
	"github.com/opencontainers/go-digest"
)

type sshfsMount struct {
	id        string
	endpoint  string
	mountPath string
	refCount  int
}

type sshfsManager struct {
	rootDir string
	mu      sync.Mutex
	mounts  map[string]*sshfsMount
}

func newSSHFSManager(rootDir string) *sshfsManager {
	return &sshfsManager{
		rootDir: rootDir,
		mounts:  map[string]*sshfsMount{},
	}
}

// ensureMounted mounts the endpoint with sshfs using the provided private/public key files (paths)
// and returns the mount id and local mount path.
func (m *sshfsManager) ensureMounted(ctx context.Context, endpoint string, privateKeyPath, publicKeyPath string) (string, string, error) {
	m.mu.Lock()
	// id is sha256(endpoint + pubKey)
	h := sha256.Sum256([]byte(endpoint + ":" + publicKeyPath))
	id := hex.EncodeToString(h[:])
	if ex, ok := m.mounts[id]; ok {
		ex.refCount++
		mp := ex.mountPath
		m.mu.Unlock()
		return id, mp, nil
	}
	// create mount dir
	mp := filepath.Join(m.rootDir, "sshfs", id)
	if err := os.MkdirAll(mp, 0o755); err != nil {
		m.mu.Unlock()
		return "", "", fmt.Errorf("failed to create mount dir: %w", err)
	}
	// run sshfs
	// sshfs -o IdentityFile=<privateKeyPath> <endpoint> <mp>
	cmd := exec.CommandContext(ctx, "sshfs", "-o", fmt.Sprintf("IdentityFile=%s", privateKeyPath), endpoint, mp)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		m.mu.Unlock()
		return "", "", fmt.Errorf("sshfs mount failed: %w", err)
	}

	mount := &sshfsMount{id: id, endpoint: endpoint, mountPath: mp, refCount: 1}
	m.mounts[id] = mount
	m.mu.Unlock()

	return id, mp, nil
}

func (m *sshfsManager) release(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ex, ok := m.mounts[id]
	if !ok {
		return fmt.Errorf("unknown sshfs mount id %s", id)
	}
	ex.refCount--
	if ex.refCount > 0 {
		return nil
	}
	// attempt to unmount
	cmd := exec.CommandContext(ctx, "fusermount", "-u", ex.mountPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// try umount fallback
		cmd2 := exec.CommandContext(ctx, "umount", ex.mountPath)
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
		_ = cmd2.Run() // ignore error; best-effort
	}
	delete(m.mounts, id)
	// remove dir
	_ = os.RemoveAll(ex.mountPath)
	return nil
}

// RegisterSSHFSVolume on the server will mount the sshfs volume and return a Volume object.
func (srv *Server) RegisterSSHFSVolume(ctx context.Context, endpoint string, privateKey digest.Digest, publicKey digest.Digest) (*core.Volume, error) {
	client, err := srv.clientFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	// retrieve secrets from client's secret store
	privPlain, err := client.secretStore.GetSecretPlaintext(ctx, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key plaintext: %w", err)
	}
	pubPlain, err := client.secretStore.GetSecretPlaintext(ctx, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key plaintext: %w", err)
	}

	// write keys to secure temp files under server root
	keysDir := filepath.Join(srv.rootDir, "ssh-keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create keys dir: %w", err)
	}
	privPath := filepath.Join(keysDir, privateKey.String())
	pubPath := filepath.Join(keysDir, publicKey.String())
	if err := os.WriteFile(privPath, privPlain, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPlain, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	if srv.sshfsMgr == nil {
		srv.sshfsMgr = newSSHFSManager(srv.rootDir)
	}

	id, mp, err := srv.sshfsMgr.ensureMounted(ctx, endpoint, privPath, pubPath)
	if err != nil {
		return nil, err
	}

	vol := &core.Volume{ID: id, MountPath: mp}
	return vol, nil
}

// helper to release a registered volume
func (srv *Server) ReleaseSSHFSVolume(ctx context.Context, id string) error {
	if srv.sshfsMgr == nil {
		return fmt.Errorf("sshfs manager not initialized")
	}
	return srv.sshfsMgr.release(ctx, id)
}
