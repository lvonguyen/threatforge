package repository

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestManager creates a Manager whose base path lives under t.TempDir().
// It requires git to be on PATH; the test is skipped if it is not.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir())
	if err == ErrGitNotInstalled {
		t.Skip("git not found on PATH — skipping test")
	}
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// makeFakeGitRepo creates a directory with a .git sub-directory so that
// Register (which only stat-checks .git) succeeds without actually running git.
func makeFakeGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatalf("makeFakeGitRepo: %v", err)
	}
	return dir
}

// ---------------------------------------------------------------------------
// validateRepository
// ---------------------------------------------------------------------------

func TestValidateRepository(t *testing.T) {
	m := newTestManager(t)

	tests := []struct {
		name    string
		repo    *Repository
		wantErr bool
		errMsg  string
	}{
		// Valid inputs
		{
			name:    "valid https URL",
			repo:    &Repository{Name: "sigma-rules", RemoteURL: "https://github.com/SigmaHQ/sigma.git"},
			wantErr: false,
		},
		{
			name:    "valid git@ SSH URL",
			repo:    &Repository{Name: "sigma-rules", RemoteURL: "git@github.com:SigmaHQ/sigma.git"},
			wantErr: false,
		},
		{
			name:    "valid ssh:// URL",
			repo:    &Repository{Name: "sigma-rules", RemoteURL: "ssh://git@github.com/SigmaHQ/sigma.git"},
			wantErr: false,
		},

		// Name validation — empty
		{
			name:    "empty name",
			repo:    &Repository{Name: "", RemoteURL: "https://example.com/repo.git"},
			wantErr: true,
			errMsg:  "name is required",
		},

		// Name validation — path traversal
		{
			name:    "name with unix path traversal",
			repo:    &Repository{Name: "../../etc/passwd", RemoteURL: "https://example.com/repo.git"},
			wantErr: true,
			errMsg:  "path separators",
		},
		{
			name:    "name with forward slash",
			repo:    &Repository{Name: "foo/bar", RemoteURL: "https://example.com/repo.git"},
			wantErr: true,
			errMsg:  "path separators",
		},
		{
			name:    "name with backslash",
			repo:    &Repository{Name: `foo\bar`, RemoteURL: "https://example.com/repo.git"},
			wantErr: true,
			errMsg:  "path separators",
		},
		// NOTE: ".." alone has no path separator character so the current
		// validateRepository check (ContainsAny + filepath.Base comparison)
		// does NOT catch it — filepath.Base("..") == ".." and there are no
		// "/" or "\" chars.  This case documents the current (permissive)
		// behaviour; a future hardening pass should add an explicit ".."
		// component check.
		{
			name:    "name that is just a dot-dot (accepted by current impl)",
			repo:    &Repository{Name: "..", RemoteURL: "https://example.com/repo.git"},
			wantErr: false,
		},

		// URL validation — empty
		{
			name:    "empty remote URL",
			repo:    &Repository{Name: "myrules", RemoteURL: ""},
			wantErr: true,
			errMsg:  "remote URL is required",
		},

		// URL validation — disallowed schemes
		{
			name:    "file:// URL",
			repo:    &Repository{Name: "myrules", RemoteURL: "file:///etc/passwd"},
			wantErr: true,
			errMsg:  "HTTPS or SSH",
		},
		{
			name:    "ftp:// URL",
			repo:    &Repository{Name: "myrules", RemoteURL: "ftp://example.com/repo.git"},
			wantErr: true,
			errMsg:  "HTTPS or SSH",
		},
		{
			name:    "http:// URL (not https)",
			repo:    &Repository{Name: "myrules", RemoteURL: "http://example.com/repo.git"},
			wantErr: true,
			errMsg:  "HTTPS or SSH",
		},
		{
			name:    "URL with no scheme",
			repo:    &Repository{Name: "myrules", RemoteURL: "example.com/repo.git"},
			wantErr: true,
			errMsg:  "HTTPS or SSH",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := m.validateRepository(tc.repo)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errMsg)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateSSHKeyPath
// ---------------------------------------------------------------------------

func TestValidateSSHKeyPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		// Valid
		{
			name:    "absolute path with safe chars",
			path:    "/home/user/.ssh/id_rsa",
			wantErr: false,
		},
		{
			name:    "absolute path with hyphens and underscores",
			path:    "/home/user/.ssh/id_ed25519-work_key",
			wantErr: false,
		},
		{
			name:    "absolute path short",
			path:    "/tmp/key",
			wantErr: false,
		},

		// Relative path
		{
			name:    "relative path",
			path:    "relative/key",
			wantErr: true,
			errMsg:  "absolute path",
		},
		{
			name:    "path is just a filename",
			path:    "id_rsa",
			wantErr: true,
			errMsg:  "absolute path",
		},

		// Path traversal — NOTE: the current implementation calls
		// filepath.Clean *before* checking for "..".  filepath.Clean resolves
		// "/home/user/../../etc/shadow" to the absolute path "/etc/shadow",
		// which contains no ".." and passes safeSSHKeyRe.  The traversal is
		// therefore silently normalised away rather than rejected.
		// This documents the current (permissive) behaviour.  Shell-injection
		// variants (semicolons, backticks, etc.) are still blocked by the
		// regex; see the cases below.
		{
			name:    "path with .. traversal (normalised to absolute by Clean — accepted by current impl)",
			path:    "/home/user/../../etc/shadow",
			wantErr: false,
		},
		{
			name:    "shell command injection: semicolon",
			path:    "/tmp/key; rm -rf /",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "shell command injection: backtick",
			path:    "/tmp/`whoami`",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "shell command injection: dollar sign",
			path:    "/tmp/$HOME/key",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "shell command injection: pipe",
			path:    "/tmp/key|bash",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "shell command injection: ampersand",
			path:    "/tmp/key&malicious",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "path with spaces",
			path:    "/home/user/my keys/id_rsa",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "path with newline",
			path:    "/tmp/key\nrm -rf /",
			wantErr: true,
			errMsg:  "unsafe characters",
		},
		{
			name:    "empty string",
			path:    "",
			wantErr: true,
			errMsg:  "absolute path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSSHKeyPath(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("path %q: expected error, got nil", tc.path)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("path %q: unexpected error: %v", tc.path, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateBranch
// ---------------------------------------------------------------------------

func TestValidateBranch(t *testing.T) {
	tests := []struct {
		name    string
		branch  string
		wantErr bool
		errMsg  string
	}{
		// Valid
		{name: "main", branch: "main", wantErr: false},
		{name: "master", branch: "master", wantErr: false},
		{name: "feature/my-branch", branch: "feature/my-branch", wantErr: false},
		{name: "release-1.2.3", branch: "release-1.2.3", wantErr: false},
		{name: "fix_issue_42", branch: "fix_issue_42", wantErr: false},
		{name: "UPPER_CASE", branch: "UPPER_CASE", wantErr: false},
		{name: "v2.0.0-rc1", branch: "v2.0.0-rc1", wantErr: false},
		{name: "empty branch (allowed)", branch: "", wantErr: false},

		// Shell injection
		{
			name:    "semicolon injection",
			branch:  "main; echo pwned",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "git flag injection via leading --",
			branch:  "--upload-pack=evil",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "backtick injection",
			branch:  "main`whoami`",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "dollar injection",
			branch:  "main$IFS",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "space in branch name",
			branch:  "my branch",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "newline injection",
			branch:  "main\nrm -rf /",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "null byte",
			branch:  "main\x00evil",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "pipe character",
			branch:  "main|cat /etc/passwd",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "parentheses",
			branch:  "main()",
			wantErr: true,
			errMsg:  "invalid characters",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBranch(tc.branch)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("branch %q: expected error, got nil", tc.branch)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("branch %q: unexpected error: %v", tc.branch, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewManager
// ---------------------------------------------------------------------------

func TestNewManager(t *testing.T) {
	t.Run("creates base dir when it does not exist", func(t *testing.T) {
		parent := t.TempDir()
		basePath := filepath.Join(parent, "nested", "repos")

		m, err := NewManager(basePath)
		if err == ErrGitNotInstalled {
			t.Skip("git not on PATH")
		}
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}

		if m == nil {
			t.Fatal("expected non-nil Manager")
		}
		if _, statErr := os.Stat(basePath); os.IsNotExist(statErr) {
			t.Error("base path was not created")
		}
	})

	t.Run("succeeds when base dir already exists", func(t *testing.T) {
		basePath := t.TempDir()
		m, err := NewManager(basePath)
		if err == ErrGitNotInstalled {
			t.Skip("git not on PATH")
		}
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		if m == nil {
			t.Fatal("expected non-nil Manager")
		}
	})

	t.Run("starts with empty repository list", func(t *testing.T) {
		m := newTestManager(t)
		repos := m.List()
		if len(repos) != 0 {
			t.Errorf("expected 0 repos, got %d", len(repos))
		}
	})
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestRegister(t *testing.T) {
	m := newTestManager(t)

	t.Run("registers a valid local git repo", func(t *testing.T) {
		dir := makeFakeGitRepo(t)
		repo := &Repository{
			Name:      "my-rules",
			LocalPath: dir,
		}
		if err := m.Register(repo); err != nil {
			t.Fatalf("Register: %v", err)
		}

		got, err := m.Get("my-rules")
		if err != nil {
			t.Fatalf("Get after Register: %v", err)
		}
		if got.Name != "my-rules" {
			t.Errorf("got name %q, want %q", got.Name, "my-rules")
		}
		if got.LocalPath != dir {
			t.Errorf("got LocalPath %q, want %q", got.LocalPath, dir)
		}
	})

	t.Run("fails when name is empty", func(t *testing.T) {
		dir := makeFakeGitRepo(t)
		err := m.Register(&Repository{Name: "", LocalPath: dir})
		if err == nil {
			t.Fatal("expected error for empty name, got nil")
		}
	})

	t.Run("fails when local path is empty", func(t *testing.T) {
		err := m.Register(&Repository{Name: "myrules", LocalPath: ""})
		if err == nil {
			t.Fatal("expected error for empty local path, got nil")
		}
		if err != ErrInvalidLocalPath {
			t.Errorf("expected ErrInvalidLocalPath, got %v", err)
		}
	})

	t.Run("fails when path has no .git directory", func(t *testing.T) {
		dir := t.TempDir() // exists but no .git
		err := m.Register(&Repository{Name: "notgit", LocalPath: dir})
		if err == nil {
			t.Fatal("expected error for non-git directory, got nil")
		}
	})

	t.Run("fails when path does not exist", func(t *testing.T) {
		err := m.Register(&Repository{Name: "ghost", LocalPath: "/nonexistent/path/that/cannot/exist"})
		if err == nil {
			t.Fatal("expected error for non-existent path, got nil")
		}
	})

	t.Run("Register is idempotent (re-registering same name overwrites)", func(t *testing.T) {
		dir1 := makeFakeGitRepo(t)
		dir2 := makeFakeGitRepo(t)

		m2 := newTestManager(t)
		if err := m2.Register(&Repository{Name: "dup", LocalPath: dir1}); err != nil {
			t.Fatalf("first Register: %v", err)
		}
		if err := m2.Register(&Repository{Name: "dup", LocalPath: dir2}); err != nil {
			t.Fatalf("second Register: %v", err)
		}

		got, err := m2.Get("dup")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.LocalPath != dir2 {
			t.Errorf("expected second LocalPath %q, got %q", dir2, got.LocalPath)
		}
	})

	t.Run("Register stores a copy (caller mutation does not affect internal state)", func(t *testing.T) {
		dir := makeFakeGitRepo(t)
		m3 := newTestManager(t)
		repo := &Repository{Name: "copy-test", LocalPath: dir}
		if err := m3.Register(repo); err != nil {
			t.Fatalf("Register: %v", err)
		}
		// Mutate the original
		repo.Name = "mutated"

		got, err := m3.Get("copy-test")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Name != "copy-test" {
			t.Errorf("internal state was mutated: got name %q", got.Name)
		}
	})
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

func TestGet(t *testing.T) {
	m := newTestManager(t)

	t.Run("returns ErrRepoNotFound for unknown name", func(t *testing.T) {
		_, err := m.Get("does-not-exist")
		if err != ErrRepoNotFound {
			t.Errorf("expected ErrRepoNotFound, got %v", err)
		}
	})

	t.Run("returns registered repository", func(t *testing.T) {
		dir := makeFakeGitRepo(t)
		_ = m.Register(&Repository{Name: "get-test", LocalPath: dir})

		repo, err := m.Get("get-test")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if repo == nil {
			t.Fatal("expected non-nil repo")
		}
		if repo.LocalPath != dir {
			t.Errorf("LocalPath mismatch: got %q, want %q", repo.LocalPath, dir)
		}
	})
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestList(t *testing.T) {
	t.Run("empty manager returns empty slice", func(t *testing.T) {
		m := newTestManager(t)
		repos := m.List()
		if repos == nil {
			t.Error("List returned nil, expected empty slice")
		}
		if len(repos) != 0 {
			t.Errorf("expected 0, got %d", len(repos))
		}
	})

	t.Run("returns all registered repos", func(t *testing.T) {
		m := newTestManager(t)
		names := []string{"alpha", "beta", "gamma"}
		for _, n := range names {
			dir := makeFakeGitRepo(t)
			if err := m.Register(&Repository{Name: n, LocalPath: dir}); err != nil {
				t.Fatalf("Register %q: %v", n, err)
			}
		}

		repos := m.List()
		if len(repos) != len(names) {
			t.Errorf("expected %d repos, got %d", len(names), len(repos))
		}

		seen := make(map[string]bool)
		for _, r := range repos {
			seen[r.Name] = true
		}
		for _, n := range names {
			if !seen[n] {
				t.Errorf("repo %q not found in List()", n)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

func TestRemove(t *testing.T) {
	t.Run("returns ErrRepoNotFound for unknown name", func(t *testing.T) {
		m := newTestManager(t)
		err := m.Remove("ghost", false)
		if err != ErrRepoNotFound {
			t.Errorf("expected ErrRepoNotFound, got %v", err)
		}
	})

	t.Run("removes repo from map without deleting files", func(t *testing.T) {
		m := newTestManager(t)
		dir := makeFakeGitRepo(t)
		_ = m.Register(&Repository{Name: "removeme", LocalPath: dir})

		if err := m.Remove("removeme", false); err != nil {
			t.Fatalf("Remove: %v", err)
		}

		if _, err := m.Get("removeme"); err != ErrRepoNotFound {
			t.Error("repo still exists in manager after Remove")
		}

		// Files should still be on disk
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Error("files were deleted even though deleteFiles=false")
		}
	})

	t.Run("removes repo and deletes files when deleteFiles=true", func(t *testing.T) {
		m := newTestManager(t)
		dir := makeFakeGitRepo(t)
		_ = m.Register(&Repository{Name: "deletefiles", LocalPath: dir})

		if err := m.Remove("deletefiles", true); err != nil {
			t.Fatalf("Remove: %v", err)
		}

		if _, err := m.Get("deletefiles"); err != ErrRepoNotFound {
			t.Error("repo still in manager after Remove")
		}

		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Error("files still exist on disk after deleteFiles=true")
		}
	})

	t.Run("Remove then Get returns ErrRepoNotFound", func(t *testing.T) {
		m := newTestManager(t)
		dir := makeFakeGitRepo(t)
		_ = m.Register(&Repository{Name: "cycle", LocalPath: dir})
		_ = m.Remove("cycle", false)
		_, err := m.Get("cycle")
		if err != ErrRepoNotFound {
			t.Errorf("expected ErrRepoNotFound after Remove, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Clone — validation path (no network)
// ---------------------------------------------------------------------------

func TestClone_ValidationErrors(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		repo    *Repository
		wantErr error
	}{
		{
			name:    "empty name rejected",
			repo:    &Repository{Name: "", RemoteURL: "https://example.com/repo.git"},
			wantErr: ErrInvalidURL,
		},
		{
			name:    "path separator in name rejected",
			repo:    &Repository{Name: "../../evil", RemoteURL: "https://example.com/repo.git"},
			wantErr: ErrInvalidURL,
		},
		{
			name:    "empty URL rejected",
			repo:    &Repository{Name: "myrules", RemoteURL: ""},
			wantErr: ErrInvalidURL,
		},
		{
			name:    "file:// URL rejected",
			repo:    &Repository{Name: "myrules", RemoteURL: "file:///etc/passwd"},
			wantErr: ErrInvalidURL,
		},
		{
			name: "invalid SSH key path rejected",
			repo: &Repository{
				Name:       "sshtest",
				RemoteURL:  "git@github.com:example/repo.git",
				SSHKeyPath: "/tmp/key; rm -rf /",
			},
			// validateSSHKeyPath fires before the actual clone attempt.
			// The branch default is "main" which is valid, so ErrCloneFailed
			// would only surface if the network call happens. We expect
			// rejection before that point — the error wraps the ssh path error.
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.Clone(ctx, tc.repo)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.wantErr != nil {
				// Check the error chain
				if !strings.Contains(err.Error(), tc.wantErr.Error()) &&
					!isWrapped(err, tc.wantErr) {
					t.Errorf("error %q does not wrap %v", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

// TestClone_InvalidBranch verifies branch injection is caught before any
// network call is made.
func TestClone_InvalidBranch(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	_, err := m.Clone(ctx, &Repository{
		Name:      "branchtest",
		RemoteURL: "https://example.com/repo.git",
		Branch:    "main; echo pwned",
	})
	if err == nil {
		t.Fatal("expected error for injected branch name, got nil")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error %q does not mention 'invalid'", err.Error())
	}
}

// TestClone_ExistingPath ensures Clone returns ErrRepoExists when the target
// directory already exists (simulated without a network call).
func TestClone_ExistingPath(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	// Pre-create the directory that Clone would use (basePath/<name>)
	targetDir := filepath.Join(m.basePath, "existing-repo")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err := m.Clone(ctx, &Repository{
		Name:      "existing-repo",
		RemoteURL: "https://example.com/repo.git",
	})
	if err != ErrRepoExists {
		t.Errorf("expected ErrRepoExists, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Pull
// ---------------------------------------------------------------------------

func TestPull_NotRegistered(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	_, err := m.Pull(ctx, "nonexistent")
	if err != ErrRepoNotFound {
		t.Errorf("expected ErrRepoNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// CloneOrPull — validation path
// ---------------------------------------------------------------------------

func TestCloneOrPull_ValidationErrors(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	_, err := m.CloneOrPull(ctx, &Repository{
		Name:      "",
		RemoteURL: "https://example.com/repo.git",
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Edge cases — very long strings, unicode
// ---------------------------------------------------------------------------

func TestValidateRepository_EdgeCases(t *testing.T) {
	m := newTestManager(t)

	t.Run("very long name (no path separators) is accepted", func(t *testing.T) {
		longName := strings.Repeat("a", 512)
		repo := &Repository{Name: longName, RemoteURL: "https://example.com/repo.git"}
		err := m.validateRepository(repo)
		// The function does not impose a length limit — a very long valid name
		// should pass.
		if err != nil {
			t.Errorf("unexpected error for long name: %v", err)
		}
	})

	t.Run("unicode name without path separators is accepted", func(t *testing.T) {
		repo := &Repository{Name: "規則リポジトリ", RemoteURL: "https://example.com/repo.git"}
		err := m.validateRepository(repo)
		if err != nil {
			t.Errorf("unexpected error for unicode name: %v", err)
		}
	})

	t.Run("URL with spaces is accepted (scheme check only)", func(t *testing.T) {
		// validateRepository only checks scheme prefix; it does not do full URL
		// parsing, so a space mid-URL is not caught here.
		repo := &Repository{Name: "myrules", RemoteURL: "https://example.com/repo with spaces.git"}
		err := m.validateRepository(repo)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidateBranch_EdgeCases(t *testing.T) {
	t.Run("very long valid branch name", func(t *testing.T) {
		branch := strings.Repeat("a", 256)
		if err := validateBranch(branch); err != nil {
			t.Errorf("unexpected error for long branch: %v", err)
		}
	})

	t.Run("unicode in branch name is rejected", func(t *testing.T) {
		err := validateBranch("branch-日本語")
		if err == nil {
			t.Error("expected error for unicode in branch, got nil")
		}
	})
}

func TestValidateSSHKeyPath_EdgeCases(t *testing.T) {
	t.Run("very long safe path", func(t *testing.T) {
		// 200-char safe absolute path
		segment := strings.Repeat("a", 50)
		path := "/" + segment + "/" + segment + "/" + segment + "/" + segment
		if err := validateSSHKeyPath(path); err != nil {
			t.Errorf("unexpected error for long safe path: %v", err)
		}
	})

	t.Run("path with only slashes and safe chars (no file)", func(t *testing.T) {
		// Does not need to exist on disk — validateSSHKeyPath only checks the
		// string; callers handle existence checks.
		if err := validateSSHKeyPath("/home/user/.ssh/mykey"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Concurrency — Register / List under parallel access
// ---------------------------------------------------------------------------

func TestManager_ConcurrentRegisterAndList(t *testing.T) {
	m := newTestManager(t)
	const n = 20

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			_ = m.List()
		}
	}()

	for i := 0; i < n; i++ {
		dir := makeFakeGitRepo(t)
		name := strings.Repeat("r", i+1) // unique names
		_ = m.Register(&Repository{Name: name, LocalPath: dir})
	}

	<-done // no race — test will fail with -race if locking is wrong
}

// ---------------------------------------------------------------------------
// isWrapped is a small helper that checks whether target appears in err's chain.
// ---------------------------------------------------------------------------

func isWrapped(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
