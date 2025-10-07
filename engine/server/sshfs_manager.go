package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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
	user, host, port, remotePath, err := parseSSHEndpoint(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("invalid sshfs endpoint %q: %w", endpoint, err)
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

	// Dynamic host candidate enrichment (no active SSH probing here).
	originalHost := host
	candidates := dynamicHostCandidates(host)
	if len(candidates) == 0 { // fallback safety
		candidates = []string{host}
	}

	var lastErr error
	var sshfsEndpoint string
	// We'll attempt mount sequentially for each candidate host until success.
	for _, cand := range candidates {
		sshfsEndpoint = fmt.Sprintf("%s@%s:%s", user, cand, remotePath)
		// Build args once per candidate; mount attempts happen later.
		portStr := port
		_ = portStr // keep naming consistent; port already string
		// Assemble arguments below after candidate loop; we attempt inside process start section.
		// We'll duplicate minimal code for clarity; break on success.
		args := []string{
			sshfsEndpoint,
			// mount path placeholder; will reuse mp constant
			mp,
			"-o", fmt.Sprintf("IdentityFile=%s", privateKeyPath),
			"-o", "IdentitiesOnly=yes",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-p", port,
		}
		if os.Getenv("DAGGER_SSHFS_DEBUG") == "1" {
			args = append(args, "-o", "sshfs_debug", "-o", "loglevel=DEBUG3")
		}
		if st, err := os.Stat("/dev/fuse"); err != nil || (st.Mode()&os.ModeDevice) == 0 {
			return "", "", fmt.Errorf("/dev/fuse not available inside engine container: %w", err)
		}
		logrus.WithFields(logrus.Fields{
			"id":            id,
			"endpoint":      sshfsEndpoint,
			"port":          port,
			"mountPath":     mp,
			"args":          args,
			"originalHost":  originalHost,
			"candidateHost": cand,
		}).Info("sshfs: mounting")

		cmd := exec.CommandContext(ctx, "sshfs", args...)
		if os.Getenv("DAGGER_SSHFS_DEBUG") == "1" {
			cmd.Stdout = os.Stdout
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			lastErr = fmt.Errorf("sshfs start failed for candidate %s: %v: %s", cand, err, stderr.String())
			continue
		}
		// readiness polling for mountpoint only (no SSH probing)
		deadline := time.Now().Add(20 * time.Second)
		mounted := false
		for !mounted && time.Now().Before(deadline) {
			if ctx.Err() != nil {
				_ = cmd.Process.Kill()
				return "", "", fmt.Errorf("context canceled while waiting for sshfs mount: %w", ctx.Err())
			}
			if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
				_ = cmd.Wait()
				lastErr = fmt.Errorf("sshfs exited early for candidate %s: %s", cand, stderr.String())
				break
			}
			if isMounted(mp) {
				mounted = true
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if !mounted {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if lastErr == nil { // ensure we have an error recorded
				lastErr = fmt.Errorf("sshfs mount readiness timeout for candidate %s: %s", cand, stderr.String())
			}
			// try next candidate
			continue
		}
		// success
		go func(pid int, c string) {
			if err := cmd.Wait(); err != nil {
				logrus.WithFields(logrus.Fields{"id": id, "pid": pid, "candidateHost": c, "err": err}).Warn("sshfs process exited with error")
			} else if os.Getenv("DAGGER_SSHFS_DEBUG") == "1" {
				logrus.WithFields(logrus.Fields{"id": id, "pid": pid, "candidateHost": c}).Debug("sshfs process exited")
			}
		}(cmd.Process.Pid, cand)
		mount := &sshfsMount{id: id, endpoint: sshfsEndpoint, mountPath: mp, refCount: 1, proc: cmd.Process}
		m.mounts[id] = mount
		logrus.WithFields(logrus.Fields{
			"id":         id,
			"endpoint":   sshfsEndpoint,
			"mountPath":  mp,
			"chosenHost": cand,
		}).Info("sshfs: mounted")
		return id, mp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no candidates attempted")
	}
	return "", "", lastErr
}

// parseSSHEndpoint accepts either scp-style user@host[:port][/path] or ssh://user@host[:port]/path
// Returns user, host, port (string), path, error.
func parseSSHEndpoint(ep string) (string, string, string, string, error) {
	if strings.HasPrefix(ep, "ssh://") {
		u, err := url.Parse(ep)
		if err != nil {
			return "", "", "", "", err
		}
		user := u.User.Username()
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "22"
		}
		p := u.Path
		if p == "" {
			p = "/"
		}
		if user == "" || host == "" {
			return "", "", "", "", fmt.Errorf("missing user or host")
		}
		return user, host, port, p, nil
	}
	// scp style: user@host:port/path OR user@host:/path OR user@host/path
	// First split user@rest
	atIdx := strings.Index(ep, "@")
	if atIdx < 0 {
		return "", "", "", "", fmt.Errorf("missing '@'")
	}
	user := ep[:atIdx]
	hostRest := ep[atIdx+1:]
	if user == "" {
		return "", "", "", "", fmt.Errorf("empty user")
	}
	// path part starts at first ':' followed by '/' or first '/'.
	var hostPart, pathPart string
	// try to find '/' that begins path
	slashIdx := strings.Index(hostRest, "/")
	if slashIdx >= 0 {
		hostPart = hostRest[:slashIdx]
		pathPart = hostRest[slashIdx:]
	} else {
		hostPart = hostRest
		pathPart = "/"
	}
	// hostPart may contain :port
	port := "22"
	if colonIdx := strings.Index(hostPart, ":"); colonIdx >= 0 {
		pStr := hostPart[colonIdx+1:]
		hostPart = hostPart[:colonIdx]
		if pStr != "" {
			if _, err := strconv.Atoi(pStr); err == nil {
				port = pStr
			}
		}
	}
	if hostPart == "" {
		return "", "", "", "", fmt.Errorf("empty host")
	}
	return user, hostPart, port, pathPart, nil
}

// dynamicHostCandidates returns possible host substitutions when original is loopback.
// It collects values from env DAGGER_SSHFS_HOST_CANDIDATES (comma-separated) and
// auto-detects default gateway via /proc/net/route (Linux) as a last resort.
func dynamicHostCandidates(host string) []string {
	candidates := []string{host}
	if !(host == "127.0.0.1" || host == "localhost" || strings.HasPrefix(host, "127.")) {
		return candidates
	}
	seen := map[string]struct{}{host: {}}
	// env provided
	if extra := os.Getenv("DAGGER_SSHFS_HOST_CANDIDATES"); extra != "" {
		for _, part := range strings.Split(extra, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; !ok {
				candidates = append(candidates, p)
				seen[p] = struct{}{}
			}
		}
	}
	// attempt default gateway detection from /proc/net/route
	if gw, err := detectLinuxGateway(); err == nil && gw != "" {
		if _, ok := seen[gw]; !ok {
			candidates = append(candidates, gw)
			seen[gw] = struct{}{}
		}
	}
	return candidates
}

func detectLinuxGateway() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Format: Iface Destination Gateway Flags ... (tab separated)
	scanner := bufio.NewScanner(f)
	// skip header
	if !scanner.Scan() {
		return "", fmt.Errorf("empty route file")
	}
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		destHex := fields[1]
		gwHex := fields[2]
		if destHex == "00000000" && gwHex != "00000000" { // default route
			// hex is little-endian
			if len(gwHex) != 8 {
				continue
			}
			// parse bytes
			b1, _ := strconv.ParseInt(gwHex[6:8], 16, 0)
			b2, _ := strconv.ParseInt(gwHex[4:6], 16, 0)
			b3, _ := strconv.ParseInt(gwHex[2:4], 16, 0)
			b4, _ := strconv.ParseInt(gwHex[0:2], 16, 0)
			ip := fmt.Sprintf("%d.%d.%d.%d", b1, b2, b3, b4)
			// basic sanity
			if net.ParseIP(ip) != nil {
				return ip, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("gateway not found")
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
