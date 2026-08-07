// Package test holds repository-level integrity checks that do not belong to
// any single implementation package.
package test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docs/rfc-compliance-matrix.md is a compliance claim. Operators read it to
// decide whether Labyrinth is safe to deploy in their environment, and a
// wrong ✅ is worse than a missing row — it converts "we haven't built that"
// into "we built and verified that".
//
// The UI matrix (web/ui/src/data/rfcCompliance.ts) is already pinned by
// rfcCompliance.test.ts. The markdown matrix was not, and drifted twice:
//
//   - RFC 9103 was marked ✅ citing `xfr/client.go`. The file is real and the
//     code is correct, but nothing in the repository imports the package, so
//     the claimed capability could not be exercised by any running binary.
//   - RFC 8305 cited `resolver/rfc8305_happy_eyeballs_test.go`, which has
//     never existed. The feature is implemented; the evidence was not.
//
// Those are two distinct failure modes, and this file pins both:
//
//	TestComplianceMatrixCitedFilesExist    — the evidence must be real
//	TestComplianceMatrixCitedPackagesLive  — the code must be reachable
//
// Neither can prove the implementation is *correct* — that is what the
// rfcNNNN_*_test.go files are for. They prove the table is not lying about
// what exists.

const moduleImportPrefix = "github.com/labyrinthdns/labyrinth/"

// repoRoot returns the repository root, resolved from this file's directory
// (test/) rather than the working directory, so the check behaves the same
// under `go test ./...` and `go test ./test/`.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(wd)
}

// citedPathRE matches a backtick-quoted repository path in the matrix. The
// `/` requirement is what separates a path from the many inline code spans
// naming Go identifiers (`hardenBelowNX`, `resolveNSHappyEyeballs`, config
// keys like `max_tcp_conns_per_client`), which are not files and must not be
// stat'ed.
var citedPathRE = regexp.MustCompile("`([A-Za-z0-9_./-]+/[A-Za-z0-9_.-]+\\.(?:go|ts|tsx|md|yaml|yml))`")

// citedPaths extracts every repository path the matrix cites, deduplicated
// and sorted for a stable failure message.
//
// compliantOnly restricts the scan to rows bearing the ✅ marker. The
// "Missing (Future Milestones)" table also cites real paths — RFC 9103 points
// at xfr/client.go to explain precisely what exists and why it still isn't
// compliance — and those citations must be checked for existence but must not
// be held to the reachability bar, which is the whole reason they are in that
// table.
func citedPaths(t *testing.T, root string, compliantOnly bool) []string {
	t.Helper()

	matrix := filepath.Join(root, "docs", "rfc-compliance-matrix.md")
	body, err := os.ReadFile(matrix)
	if err != nil {
		t.Fatalf("read %s: %v", matrix, err)
	}

	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		// Only table rows are claims. Prose above and below the tables
		// discusses paths and status markers too — the 2026-08-07 correction
		// note names both `xfr/client.go` and ✅ in one sentence — and reading
		// that as a compliance row would resurrect the very bug this test
		// exists to catch.
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		// A compliance claim is a four-column row whose Status cell is
		// exactly ✅. Substring-matching the glyph is not enough: the
		// "Missing (Future Milestones)" row for RFC 9103 explains that it
		// "was previously listed as ✅ in error", and that sentence must not
		// read as a claim.
		if compliantOnly && !isCompliantRow(line) {
			continue
		}
		for _, m := range citedPathRE.FindAllStringSubmatch(line, -1) {
			seen[m[1]] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("no file paths found in the compliance matrix — the citation " +
			"format changed and this test has stopped checking anything")
	}

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// isCompliantRow reports whether a markdown line is a row of the main
// compliance table asserting ✅. The table shape is
// `| RFC | Title | Status | Evidence |`, so splitting on the pipe yields a
// leading empty cell and the status lands at index 3.
func isCompliantRow(line string) bool {
	cells := strings.Split(strings.TrimSpace(line), "|")
	if len(cells) < 5 {
		return false // section header rows and the 3-column Missing table
	}
	return strings.TrimSpace(cells[3]) == "✅"
}

// TestComplianceMatrixCitedFilesExist pins that every file the matrix offers
// as evidence is actually in the tree. A renamed or deleted test file silently
// turns a verified claim into an unverifiable one; this makes that a build
// failure instead.
func TestComplianceMatrixCitedFilesExist(t *testing.T) {
	root := repoRoot(t)

	for _, p := range citedPaths(t, root, false) {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("compliance matrix cites %q as evidence, but it does not exist "+
				"(%v) — either restore the file or correct the citation", p, err)
		}
	}
}

// TestComplianceMatrixCitedPackagesLive pins the harder half: a ✅ row must
// point at code some binary can actually run. A package that nothing imports
// is an unreleased feature, and belongs in the "Missing (Future Milestones)"
// table until it is wired up.
//
// The check is deliberately coarse — one importer anywhere outside the
// package's own directory is enough. It is not trying to prove the feature is
// reachable at runtime under a given config; it is trying to catch the case
// where the answer is unambiguously "no", as it was for xfr/.
func TestComplianceMatrixCitedPackagesLive(t *testing.T) {
	root := repoRoot(t)

	// Collect the package directory of every cited non-test Go file.
	pkgDirs := map[string]string{} // dir -> the path that cited it
	for _, p := range citedPaths(t, root, true) {
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(p))
		if dir == "." || dir == "" {
			continue // package main at the root is the binary; always live
		}
		if _, ok := pkgDirs[dir]; !ok {
			pkgDirs[dir] = p
		}
	}
	if len(pkgDirs) == 0 {
		t.Fatal("no implementation packages cited by the matrix — the citation " +
			"format changed and this test has stopped checking anything")
	}

	importers := importedPackages(t, root)

	dirs := make([]string, 0, len(pkgDirs))
	for d := range pkgDirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		if importers[dir] == 0 {
			t.Errorf("compliance matrix claims %q via %s, but no package outside %s/ "+
				"imports %s%s — the code is unreachable, so the claim is not "+
				"compliance. Move the row to \"Missing (Future Milestones)\" or "+
				"wire the package up.", dir, pkgDirs[dir], dir, moduleImportPrefix, dir)
		}
	}
}

// importedPackages walks the repository and counts, for each in-module package
// directory, how many *other* directories import it.
func importedPackages(t *testing.T, root string) map[string]int {
	t.Helper()

	counts := map[string]int{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			// .temp_files holds a snapshot copy of the whole tree; counting
			// its imports would make any dead package look alive.
			case ".git", ".temp_files", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fromDir := filepath.ToSlash(filepath.Dir(rel))

		for _, line := range strings.Split(string(body), "\n") {
			idx := strings.Index(line, `"`+moduleImportPrefix)
			if idx < 0 {
				continue
			}
			rest := line[idx+1+len(moduleImportPrefix):]
			end := strings.IndexByte(rest, '"')
			if end < 0 {
				continue
			}
			imported := rest[:end]
			if imported == fromDir {
				continue // a package's own test files don't count
			}
			counts[imported]++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}

	return counts
}
