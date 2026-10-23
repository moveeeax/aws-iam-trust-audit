package iampolicy

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Role is a role with its trust policy and where it was read from.
type Role struct {
	Name      string
	Arn       string
	AccountID string
	File      string
	Trust     *Document
}

// LoadDir reads every *.json file under dir and returns the roles found.
// A file is accepted in four shapes: a bare trust policy document, an
// `aws iam get-role` response, an `aws iam list-roles` response, or a plain
// array of role objects.
func LoadDir(dir string) ([]Role, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	if !info.IsDir() {
		files = []string{dir}
	} else {
		err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(path), ".json") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	var roles []Role
	for _, f := range files {
		got, err := LoadFile(f)
		if err != nil {
			return nil, err
		}
		roles = append(roles, got...)
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("no trust policies found under %s", dir)
	}
	return roles, nil
}

// LoadFile reads one file and returns the roles it describes.
func LoadFile(path string) ([]Role, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roles, err := decode(path, data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return roles, nil
}

func decode(path string, data []byte) ([]Role, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, err
		}
		var roles []Role
		for i, it := range items {
			got, err := decodeObject(path, it, i)
			if err != nil {
				return nil, err
			}
			roles = append(roles, got...)
		}
		return roles, nil
	}
	return decodeObject(path, data, -1)
}

func decodeObject(path string, data json.RawMessage, idx int) ([]Role, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	if raw, ok := pick(obj, "Roles"); ok {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		var roles []Role
		for i, it := range items {
			r, err := roleFromObject(path, it, i)
			if err != nil {
				return nil, err
			}
			roles = append(roles, r)
		}
		return roles, nil
	}
	if raw, ok := pick(obj, "Role"); ok {
		r, err := roleFromObject(path, raw, -1)
		if err != nil {
			return nil, err
		}
		return []Role{r}, nil
	}
	if _, ok := pick(obj, "AssumeRolePolicyDocument"); ok {
		r, err := roleFromObject(path, data, idx)
		if err != nil {
			return nil, err
		}
		return []Role{r}, nil
	}
	// A bare trust policy document: the file name is the only name available.
	doc, err := ParseDocument(data)
	if err != nil {
		return nil, err
	}
	return []Role{{Name: nameFromPath(path), File: path, Trust: doc}}, nil
}

func roleFromObject(path string, data json.RawMessage, idx int) (Role, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return Role{}, err
	}
	r := Role{File: path, Name: nameFromPath(path)}
	if idx >= 0 {
		r.Name = fmt.Sprintf("%s[%d]", r.Name, idx)
	}
	if raw, ok := pick(obj, "RoleName"); ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && s != "" {
			r.Name = s
		}
	}
	if raw, ok := pick(obj, "Arn"); ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			r.Arn = s
			r.AccountID = AccountFromArn(s)
		}
	}
	raw, ok := pick(obj, "AssumeRolePolicyDocument")
	if !ok {
		return Role{}, fmt.Errorf("role %q has no AssumeRolePolicyDocument", r.Name)
	}
	doc, err := parseEmbeddedDocument(raw)
	if err != nil {
		return Role{}, fmt.Errorf("role %q: %w", r.Name, err)
	}
	r.Trust = doc
	return r, nil
}

// pick looks up a key case-insensitively: hand-maintained files and Terraform
// output do not always keep the AWS capitalisation.
func pick(obj map[string]json.RawMessage, key string) (json.RawMessage, bool) {
	if v, ok := obj[key]; ok {
		return v, true
	}
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// AccountFromArn returns the account id field of an ARN, or "".
func AccountFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

func nameFromPath(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}
