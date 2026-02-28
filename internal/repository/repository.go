// Package repository provides git repository management for ThreatForge.
// It supports cloning remote repositories to local storage for rule syncing.
package repository

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrInvalidURL       = errors.New("invalid repository URL")
	ErrCloneFailed      = errors.New("git clone failed")
	ErrPullFailed       = errors.New("git pull failed")
	ErrRepoNotFound     = errors.New("repository not found")
	ErrRepoExists       = errors.New("repository already exists")
	ErrGitNotInstalled  = errors.New("git is not installed")
	ErrInvalidLocalPath = errors.New("invalid local path")
	ErrInvalidBranch    = errors.New("invalid branch name")
)

// Repository represents a git repository configuration.
type Repository struct {
	// Name is a unique identifier for this repository.
	Name string `yaml:"name" json:"name"`

	// RemoteURL is the git remote URL (HTTPS or SSH).
	RemoteURL string `yaml:"remote_url" json:"remote_url"`

	// LocalPath is the local directory where the repo is cloned.
	LocalPath string `yaml:"local_path" json:"local_path"`

	// Branch to checkout (default: main).
	Branch string `yaml:"branch" json:"branch"`

	// Depth for shallow clone (0 = full clone).
	Depth int `yaml:"depth" json:"depth"`

	// AutoSync enables automatic periodic syncing.
	AutoSync bool `yaml:"auto_sync" json:"auto_sync"`

	// SyncInterval is how often to sync if AutoSync is enabled.
	SyncInterval time.Duration `yaml:"sync_interval" json:"sync_interval"`

	// SSHKeyPath is the path to SSH private key (for SSH URLs).
	SSHKeyPath string `yaml:"ssh_key_path" json:"ssh_key_path"`
}

// CloneResult contains the result of a clone operation.
type CloneResult struct {
	Repository *Repository
	Success    bool
	Message    string
	CommitHash string
	ClonedAt   time.Time
	Duration   time.Duration
}

// Manager handles repository operations.
type Manager struct {
	mu           sync.RWMutex
	repositories map[string]*Repository
	basePath     string
	gitPath      string
}

// NewManager creates a new repository manager.
func NewManager(basePath string) (*Manager, error) {
	// Verify git is installed
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, ErrGitNotInstalled
	}

	// Create base path if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base path: %w", err)
	}

	return &Manager{
		repositories: make(map[string]*Repository),
		basePath:     basePath,
		gitPath:      gitPath,
	}, nil
}

// Clone clones a remote repository to local storage.
func (m *Manager) Clone(ctx context.Context, repo *Repository) (*CloneResult, error) {
	if err := m.validateRepository(repo); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	start := time.Now()

	// Determine local path
	localPath := repo.LocalPath
	if localPath == "" {
		localPath = filepath.Join(m.basePath, repo.Name)
	}

	// Check if already exists
	if _, err := os.Stat(localPath); err == nil {
		return nil, ErrRepoExists
	}

	// Build git clone command
	args := []string{"clone"}

	// Add depth for shallow clone
	if repo.Depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", repo.Depth))
	}

	// Add branch if specified
	branch := repo.Branch
	if branch == "" {
		branch = "main"
	}
	if err := validateBranch(branch); err != nil {
		return nil, err
	}
	args = append(args, "--branch", branch)

	// Add single-branch for efficiency
	args = append(args, "--single-branch")

	// Add remote URL and local path
	args = append(args, repo.RemoteURL, localPath)

	// Execute git clone
	cmd := exec.CommandContext(ctx, m.gitPath, args...)

	// Configure SSH key if provided (validate path to prevent injection)
	if repo.SSHKeyPath != "" {
		if err := validateSSHKeyPath(repo.SSHKeyPath); err != nil {
			return nil, err
		}
		cleanPath := filepath.Clean(repo.SSHKeyPath)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=accept-new", cleanPath),
		)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Clean up partial clone
		os.RemoveAll(localPath)
		return &CloneResult{
			Repository: repo,
			Success:    false,
			Message:    fmt.Sprintf("clone failed: %s", strings.TrimSpace(string(output))),
			ClonedAt:   time.Now(),
			Duration:   time.Since(start),
		}, fmt.Errorf("%w: %s", ErrCloneFailed, string(output))
	}

	// Get commit hash
	commitHash, _ := m.getHeadCommit(ctx, localPath)

	// Store a copy of the repository config so that subsequent mutations by the
	// caller do not silently alter the manager's internal state.
	repo.LocalPath = localPath
	stored := *repo
	m.repositories[repo.Name] = &stored

	return &CloneResult{
		Repository: repo,
		Success:    true,
		Message:    "repository cloned successfully",
		CommitHash: commitHash,
		ClonedAt:   time.Now(),
		Duration:   time.Since(start),
	}, nil
}

// CloneOrPull clones a repository if it doesn't exist, or pulls if it does.
func (m *Manager) CloneOrPull(ctx context.Context, repo *Repository) (*CloneResult, error) {
	// Validate before any operation — Pull bypasses Clone's validateRepository call.
	if err := m.validateRepository(repo); err != nil {
		return nil, err
	}

	localPath := repo.LocalPath
	if localPath == "" {
		localPath = filepath.Join(m.basePath, repo.Name)
	}

	// Check if repo already exists locally
	if _, err := os.Stat(filepath.Join(localPath, ".git")); err == nil {
		// Repository exists on disk. Ensure it is registered in the map before
		// calling Pull (which requires map registration). This handles the case
		// where the process restarted and the in-memory map was cleared.
		repo.LocalPath = localPath
		_ = m.Register(repo) // idempotent: no-op if already registered
		return m.Pull(ctx, repo.Name)
	}

	// Clone the repository
	return m.Clone(ctx, repo)
}

// Pull updates an existing local repository.
func (m *Manager) Pull(ctx context.Context, name string) (*CloneResult, error) {
	m.mu.RLock()
	repo, exists := m.repositories[name]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrRepoNotFound
	}

	start := time.Now()

	// Execute git pull
	cmd := exec.CommandContext(ctx, m.gitPath, "pull", "--ff-only")
	cmd.Dir = repo.LocalPath

	if repo.SSHKeyPath != "" {
		if err := validateSSHKeyPath(repo.SSHKeyPath); err != nil {
			return nil, err
		}
		cleanPath := filepath.Clean(repo.SSHKeyPath)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=accept-new", cleanPath),
		)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return &CloneResult{
			Repository: repo,
			Success:    false,
			Message:    fmt.Sprintf("pull failed: %s", strings.TrimSpace(string(output))),
			Duration:   time.Since(start),
		}, fmt.Errorf("%w: %s", ErrPullFailed, string(output))
	}

	commitHash, _ := m.getHeadCommit(ctx, repo.LocalPath)

	return &CloneResult{
		Repository: repo,
		Success:    true,
		Message:    strings.TrimSpace(string(output)),
		CommitHash: commitHash,
		Duration:   time.Since(start),
	}, nil
}

// Get returns a repository by name.
func (m *Manager) Get(name string) (*Repository, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	repo, exists := m.repositories[name]
	if !exists {
		return nil, ErrRepoNotFound
	}
	return repo, nil
}

// List returns all managed repositories.
func (m *Manager) List() []*Repository {
	m.mu.RLock()
	defer m.mu.RUnlock()

	repos := make([]*Repository, 0, len(m.repositories))
	for _, repo := range m.repositories {
		repos = append(repos, repo)
	}
	return repos
}

// Remove removes a repository from management and optionally deletes local files.
func (m *Manager) Remove(name string, deleteFiles bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	repo, exists := m.repositories[name]
	if !exists {
		return ErrRepoNotFound
	}

	if deleteFiles && repo.LocalPath != "" {
		if err := os.RemoveAll(repo.LocalPath); err != nil {
			return fmt.Errorf("failed to delete repository files: %w", err)
		}
	}

	delete(m.repositories, name)
	return nil
}

// Status returns the current status of a repository.
func (m *Manager) Status(ctx context.Context, name string) (*RepositoryStatus, error) {
	m.mu.RLock()
	repo, exists := m.repositories[name]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrRepoNotFound
	}

	status := &RepositoryStatus{
		Name:      name,
		LocalPath: repo.LocalPath,
		RemoteURL: repo.RemoteURL,
		Branch:    repo.Branch,
	}

	// Check if local path exists
	if _, err := os.Stat(repo.LocalPath); os.IsNotExist(err) {
		status.Exists = false
		return status, nil
	}
	status.Exists = true

	// Get current branch
	cmd := exec.CommandContext(ctx, m.gitPath, "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repo.LocalPath
	if output, err := cmd.Output(); err == nil {
		status.CurrentBranch = strings.TrimSpace(string(output))
	}

	// Get current commit
	status.CommitHash, _ = m.getHeadCommit(ctx, repo.LocalPath)

	// Check for uncommitted changes
	cmd = exec.CommandContext(ctx, m.gitPath, "status", "--porcelain")
	cmd.Dir = repo.LocalPath
	if output, err := cmd.Output(); err == nil {
		status.HasChanges = len(strings.TrimSpace(string(output))) > 0
	}

	return status, nil
}

// RepositoryStatus represents the current status of a repository.
type RepositoryStatus struct {
	Name          string `json:"name"`
	LocalPath     string `json:"local_path"`
	RemoteURL     string `json:"remote_url"`
	Branch        string `json:"branch"`
	CurrentBranch string `json:"current_branch"`
	CommitHash    string `json:"commit_hash"`
	Exists        bool   `json:"exists"`
	HasChanges    bool   `json:"has_changes"`
}

// validateRepository validates repository configuration.
func (m *Manager) validateRepository(repo *Repository) error {
	if repo.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidURL)
	}

	// Guard against path traversal: name must be a simple identifier
	if filepath.Base(repo.Name) != repo.Name || strings.ContainsAny(repo.Name, `/\`) {
		return fmt.Errorf("%w: name must not contain path separators", ErrInvalidURL)
	}

	if repo.RemoteURL == "" {
		return fmt.Errorf("%w: remote URL is required", ErrInvalidURL)
	}

	// Basic URL validation
	if !strings.HasPrefix(repo.RemoteURL, "https://") &&
		!strings.HasPrefix(repo.RemoteURL, "git@") &&
		!strings.HasPrefix(repo.RemoteURL, "ssh://") {
		return fmt.Errorf("%w: URL must be HTTPS or SSH format", ErrInvalidURL)
	}

	// SSRF protection: for HTTPS URLs, resolve the hostname and reject internal addresses.
	if strings.HasPrefix(repo.RemoteURL, "https://") {
		// Extract host from the URL (strip scheme and path)
		withoutScheme := strings.TrimPrefix(repo.RemoteURL, "https://")
		host := withoutScheme
		if idx := strings.IndexAny(withoutScheme, "/?#"); idx >= 0 {
			host = withoutScheme[:idx]
		}
		// Strip port if present
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if isInternalHost(host) {
			return fmt.Errorf("%w: HTTPS URL resolves to an internal address", ErrInvalidURL)
		}
	}

	return nil
}

// isInternalHost resolves a hostname and returns true if any resolved address
// falls within RFC 1918 private ranges, loopback, link-local (IMDS), or
// IPv6 loopback/link-local ranges.
func isInternalHost(host string) bool {
	// Private and reserved CIDR ranges to block
	internalCIDRs := []string{
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local / AWS IMDS
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique-local
	}

	var internalNets []*net.IPNet
	for _, cidr := range internalCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			internalNets = append(internalNets, ipNet)
		}
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		// Fail closed: if we cannot resolve, reject to be safe
		return true
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		for _, ipNet := range internalNets {
			if ipNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// getHeadCommit returns the current HEAD commit hash.
func (m *Manager) getHeadCommit(ctx context.Context, localPath string) (string, error) {
	cmd := exec.CommandContext(ctx, m.gitPath, "rev-parse", "HEAD")
	cmd.Dir = localPath
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// Register adds an existing local repository to management.
func (m *Manager) Register(repo *Repository) error {
	if repo.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidURL)
	}

	if repo.LocalPath == "" {
		return ErrInvalidLocalPath
	}

	// Verify it's a git repository
	gitDir := filepath.Join(repo.LocalPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s is not a git repository", ErrRepoNotFound, repo.LocalPath)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Store a copy so caller mutations don't silently alter internal state.
	copied := *repo
	m.repositories[repo.Name] = &copied
	return nil
}

// validateSSHKeyPath validates an SSH key path and returns an error if it is unsafe.
// It checks that the path is absolute, contains no ".." traversal, and consists
// only of characters that are safe to embed in a shell command string.
func validateSSHKeyPath(keyPath string) error {
	cleanPath := filepath.Clean(keyPath)
	if !filepath.IsAbs(cleanPath) || strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid SSH key path: must be an absolute path without traversal")
	}
	if !safeSSHKeyRe.MatchString(cleanPath) {
		return fmt.Errorf("invalid SSH key path: contains unsafe characters: %s", cleanPath)
	}
	return nil
}

// safeBranchRe matches valid git branch names: alphanumeric, hyphens, dots,
// underscores, and slashes. Rejects shell metacharacters and whitespace.
var safeBranchRe = regexp.MustCompile(`^[a-zA-Z0-9._\-/]+$`)

// safeSSHKeyRe matches SSH key paths containing only safe characters.
// Prevents shell metacharacter injection even when %q is not used.
var safeSSHKeyRe = regexp.MustCompile(`^[a-zA-Z0-9/._-]+$`)

// validateBranch checks that a branch name contains only safe characters.
func validateBranch(branch string) error {
	if branch == "" {
		return nil
	}
	if !safeBranchRe.MatchString(branch) {
		return fmt.Errorf("%w: branch %q contains invalid characters", ErrInvalidBranch, branch)
	}
	return nil
}
