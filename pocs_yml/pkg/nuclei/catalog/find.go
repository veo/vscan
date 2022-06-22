package catalog

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// GetTemplatePath parses the specified input template path and returns a compiled
// list of finished absolute paths to the templates evaluating any glob patterns
// or folders provided as in.
func (c *Catalog) GetTemplatePath(Pocs embed.FS) ([]string, error) {
	processed := make(map[string]struct{})
	// Recursively walk down the Templates directory and run all
	// the template file checks
	matches, err := c.findDirectoryMatches(Pocs, processed)
	if err != nil {
		return nil, errors.Wrap(err, "could not find directory matches")
	}
	if len(matches) == 0 {
		return nil, errors.New("no templates found in path")
	}
	return matches, nil
}

// findGlobPathMatches returns the matched files from a glob path
func (c *Catalog) findGlobPathMatches(absPath string, processed map[string]struct{}) ([]string, error) {
	matches, err := filepath.Glob(absPath)
	if err != nil {
		return nil, errors.Errorf("wildcard found, but unable to glob: %s\n", err)
	}
	results := make([]string, 0, len(matches))
	for _, match := range matches {
		if _, ok := processed[match]; !ok {
			processed[match] = struct{}{}
			results = append(results, match)
		}
	}
	return results, nil
}

// findFileMatches finds if a path is an absolute file. If the path
// is a file, it returns true otherwise false with no errors.
func (c *Catalog) findFileMatches(absPath string, processed map[string]struct{}) (match string, matched bool, err error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() {
		return "", false, nil
	}
	if _, ok := processed[absPath]; !ok {
		processed[absPath] = struct{}{}
		return absPath, true, nil
	}
	return "", true, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (c *Catalog) findDirectoryMatches(Pocs embed.FS, processed map[string]struct{}) ([]string, error) {
	var results []string
	err := fs.WalkDir(Pocs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			if _, ok := processed[path]; !ok {
				results = append(results, path)
				processed[path] = struct{}{}
			}
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			results = append(results, path)
		}
		return nil
	})
	return results, err
}
