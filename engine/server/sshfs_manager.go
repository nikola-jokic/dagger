package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
    "syscall"

	"github.com/dagger/dagger/core"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
)

type sshfsMount struct {
	id        string
	endpoint  string
	mountPath string
	refCount  int
	proc      *os.Process
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
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse endpoint url %q: %w", endpoint, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// id is sha256(endpoint + pubKey path)
	h := sha256.Sum256([]byte(endpoint + ":" + publicKeyPath))
	id := hex.EncodeToString(h[:])
	if ex, ok := m.mounts[id]; ok {
		ex.refCount++
		logrus.WithFields(logrus.Fields{
			"id":        id,
			"endpoint":  ex.endpoint,
			"mountPath": ex.mountPath,
			"refCount":  ex.refCount,
		}).Info("sshfs: reusing existing mount")
		return id, ex.mountPath, nil
	}

	// create mount dir
	mp := filepath.Join(m.rootDir, "sshfs", id)
	if err := os.MkdirAll(mp, 0o755); err != nil {
		return "", "", fmt.Errorf("failed to create mount dir: %w", err)
	}

	// Reconstruct the scp-style endpoint for sshfs
	user := parsedURL.User.Username()
	host := parsedURL.Hostname()
	if user == "" || host == "" {
		return "", "", fmt.Errorf("invalid endpoint, missing user or host: %s", endpoint)
	}
	remotePath := parsedURL.Path
	if remotePath == "" {
		remotePath = "/"
	}
	port := "22"
	if p := parsedURL.Port(); p != "" {
		port = p
	}

	// If the provided host looks like a loopback and we're inside a container, we may
	// need to try alternative hostnames/IPs to reach the host network listener created
	// by the tunnel. We'll attempt a small set of well-known Docker host gateway names.
	originalHost := host
	var hostCandidates []string
	if host == "127.0.0.1" || host == "localhost" || strings.HasPrefix(host, "127.") {
		hostCandidates = append(hostCandidates,
			host, // original (in case it actually works)
			"host.docker.internal",
			"gateway.docker.internal",
			"docker.for.mac.host.internal",
			"docker.for.win.host.internal",
			"docker.for.lin.host.internal",
			"172.17.0.1", // common default bridge gateway
		)
	} else {
		hostCandidates = []string{host}
	}

	// attempt readiness across candidates; pick the first that succeeds
	var chosenHost string
	for _, cand := range hostCandidates {
		for attempt := 0; attempt < 5; attempt++ {
			probe := exec.CommandContext(ctx, "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-i", privateKeyPath, "-p", port, fmt.Sprintf("%s@%s", user, cand), "true")
			if err := probe.Run(); err == nil {
				chosenHost = cand
				if cand != originalHost {
					logrus.WithFields(logrus.Fields{"id": id, "originalHost": originalHost, "chosenHost": cand}).Info("sshfs: substituted host for loopback connectivity")
				}
				break
			}
			if attempt == 4 {
				logrus.WithFields(logrus.Fields{"id": id, "candidate": cand}).Warn("sshfs: readiness failed for candidate host")
			} else {
				select {
				case <-ctx.Done():
					return "", "", fmt.Errorf("sshfs readiness probe context canceled: %w", ctx.Err())
				case <-time.After(150 * time.Millisecond):
				}
			}
		}
		if chosenHost != "" {
			break
		}
	}
	if chosenHost == "" {
		// No candidate succeeded; we'll proceed with original host but log a warning.
		chosenHost = host
		logrus.WithFields(logrus.Fields{"id": id, "host": host, "candidates": hostCandidates}).Warn("sshfs: all readiness probes failed; proceeding anyway (mount may fail)")
	}

	sshfsEndpoint := fmt.Sprintf("%s@%s:%s", user, chosenHost, remotePath)

	// sshfs command with relaxed host key checking for test environment
	args := []string{
		sshfsEndpoint,
		mp,
		"-o", fmt.Sprintf("IdentityFile=%s", privateKeyPath),
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", port,
	}

	// Preflight: ensure remote path exists (ls -ld). This gives us richer stderr if it fails.
	preflight := exec.CommandContext(ctx, "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-i", privateKeyPath, "-p", port, fmt.Sprintf("%s@%s", user, chosenHost), "ls", "-ld", remotePath)
	var pfStderr bytes.Buffer
	preflight.Stderr = &pfStderr
	if err := preflight.Run(); err != nil {
		logrus.WithFields(logrus.Fields{"id": id, "endpoint": sshfsEndpoint, "stderr": pfStderr.String(), "err": err}).Warn("sshfs: preflight ls failed (continuing)")
	} else {
		logrus.WithFields(logrus.Fields{"id": id, "endpoint": sshfsEndpoint}).Info("sshfs: preflight ls succeeded")
	}

	// add verbose debug options only if explicitly enabled to avoid noisy production logs
	if os.Getenv("DAGGER_SSHFS_DEBUG") == "1" {
		args = append(args, "-o", "sshfs_debug", "-o", "loglevel=DEBUG3")
	}

	// quick fuse availability check before starting sshfs (helpful for clearer error)
	if st, err := os.Stat("/dev/fuse"); err != nil || (st.Mode()&os.ModeDevice) == 0 {
		return "", "", fmt.Errorf("/dev/fuse not available inside engine container: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"id":           id,
		"endpoint":     sshfsEndpoint,
		"port":         port,
		"mountPath":    mp,
		"args":         args,
		"originalHost": originalHost,
	}).Info("sshfs: mounting")

	cmd := exec.CommandContext(ctx, "sshfs", args...)
	// we don't stream stdout unless debug enabled; stderr captured for diagnostics
	if os.Getenv("DAGGER_SSHFS_DEBUG") == "1" {
		cmd.Stdout = os.Stdout
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("sshfs start failed (endpoint=%s): %v: %s", sshfsEndpoint, err, stderr.String())
	}

	// readiness polling: wait up to 20s for mountpoint to appear in /proc/self/mountinfo
	deadline := time.Now().Add(20 * time.Second)
	mounted := false
	for !mounted && time.Now().Before(deadline) {
		if ctx.Err() != nil {
			// attempt to cleanup process if context canceled
			_ = cmd.Process.Kill()
			return "", "", fmt.Errorf("context canceled while waiting for sshfs mount: %w", ctx.Err())
		}
		// has process already exited unexpectedly?
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			// collect final wait output
			_ = cmd.Wait()
			return "", "", fmt.Errorf("sshfs exited before mount ready (endpoint=%s): %s", sshfsEndpoint, stderr.String())
		}
		if isMounted(mp) {
			mounted = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !mounted {
		// finalize wait to get potential exit error
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", "", fmt.Errorf("sshfs mount readiness timeout after 20s (endpoint=%s): %s", sshfsEndpoint, stderr.String())
	}

	// reap sshfs in background when it eventually exits
	go func(pid int) {
		if err := cmd.Wait(); err != nil {
			logrus.WithFields(logrus.Fields{"id": id, "pid": pid, "err": err}).Warn("sshfs process exited with error")
		} else if os.Getenv("DAGGER_SSHFS_DEBUG") == "1" {
			logrus.WithFields(logrus.Fields{"id": id, "pid": pid}).Debug("sshfs process exited")
		}
	}(cmd.Process.Pid)

	mount := &sshfsMount{id: id, endpoint: sshfsEndpoint, mountPath: mp, refCount: 1, proc: cmd.Process}
	m.mounts[id] = mount

	logrus.WithFields(logrus.Fields{
		"id":        id,
		"endpoint":  sshfsEndpoint,
		"mountPath": mp,
	}).Info("sshfs: mounted")

	return id, mp, nil
}

// isMounted checks /proc/self/mountinfo for the given mount point path.
func isMounted(mountPath string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	// naive substring match bounded by spaces and slash; acceptable for internal use
	// lines look like: <id> <parent> <major:minor> <root> <mountPoint> <options> ...
	needle := []byte(" " + mountPath + " ")
	return bytes.Contains(data, needle)
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
		logrus.WithFields(logrus.Fields{
			"id":       id,
			"refCount": ex.refCount,
		}).Info("sshfs: mount still in use")
		return nil
	}
	// attempt to unmount
	logrus.WithFields(logrus.Fields{
		"id":        id,
		"mountPath": ex.mountPath,
	}).Info("sshfs: unmounting")
	cmd := exec.CommandContext(ctx, "fusermount", "-u", ex.mountPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Warn("sshfs: fusermount failed, falling back to umount")
		// try umount fallback
		cmd2 := exec.CommandContext(ctx, "umount", ex.mountPath)
		cmd2.Stdout = os.Stdout
		cmd2.Stderr = os.Stderr
		_ = cmd2.Run() // ignore error; best-effort
	}
	delete(m.mounts, id)
	// ensure background process is gone (best effort)
	if ex.proc != nil {
		// if it's still running after unmount, kill it
		if err := ex.proc.Signal(os.Signal(syscall.Signal(0))); err == nil { // process likely alive
			_ = ex.proc.Kill()
		}
	}
	// remove dir
	_ = os.RemoveAll(ex.mountPath)
	logrus.WithField("id", id).Info("sshfs: unmounted and cleaned up")
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
