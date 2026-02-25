// Copyright The micromize authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	securejoin "github.com/cyphar/filepath-securejoin"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/singleflight"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

var imageAnnotationKeys = []string{
	"io.kubernetes.cri.image-name",
	"io.kubernetes.cri-o.ImageName",
	"io.containerd.image.name",
}

type result struct {
	HasSBOM bool
	SBOM    []byte
}

type Fetcher struct {
	cache sync.Map
	group singleflight.Group
}

func NewFetcher() *Fetcher {
	return &Fetcher{}
}

// FetchForImage fetches the SPDX SBOM for the given image reference.
// Repeated calls for the same image are served from cache.
func (f *Fetcher) FetchForImage(ctx context.Context, imageRef string) ([]byte, error) {
	if imageRef == "" {
		return nil, nil
	}

	if cached, ok := f.cache.Load(imageRef); ok {
		r := cached.(*result)
		if !r.HasSBOM {
			slog.Debug("Image previously checked, no SBOM available", "image", imageRef)
			return nil, nil
		}
		slog.Debug("Returning cached SBOM", "image", imageRef)
		return r.SBOM, nil
	}

	v, err, _ := f.group.Do(imageRef, func() (any, error) {
		sbomBytes, err := fetchSPDXSBOM(ctx, imageRef)
		if err != nil {
			// Don't cache errors — they may be transient (auth, network).
			return nil, fmt.Errorf("fetching SBOM for image %s: %w", imageRef, err)
		}

		if sbomBytes == nil {
			slog.Debug("No SPDX SBOM attached to image", "image", imageRef)
			f.cache.Store(imageRef, &result{HasSBOM: false})
			return nil, nil
		}

		slog.Debug("Fetched SPDX SBOM for image", "image", imageRef, "size", len(sbomBytes))
		f.cache.Store(imageRef, &result{HasSBOM: true, SBOM: sbomBytes})
		return sbomBytes, nil
	})
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	return v.([]byte), nil
}

// ImageRefFromOCIConfig parses the OCI runtime spec config JSON and extracts
// the container image reference from well-known annotations.
func ImageRefFromOCIConfig(ociConfig string) (string, error) {
	if ociConfig == "" {
		return "", nil
	}

	var config struct {
		Annotations map[string]string `json:"annotations,omitempty"`
	}
	if err := json.Unmarshal([]byte(ociConfig), &config); err != nil {
		return "", fmt.Errorf("parsing OCI config: %w", err)
	}

	for _, key := range imageAnnotationKeys {
		if ref, ok := config.Annotations[key]; ok && ref != "" {
			return ref, nil
		}
	}

	slog.Debug("No known image annotation found in OCI config", "annotations", config.Annotations)
	return "", nil
}

var containerIDRegexp = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

// ImageRefFromDockerConfig reads Docker's config.v2.json for the given
// container ID and extracts the image reference. This is needed because
// Docker does not set CRI image annotations in the OCI runtime spec.
func ImageRefFromDockerConfig(containerID string) string {
	if !containerIDRegexp.MatchString(containerID) {
		return ""
	}

	for _, root := range dockerDataRootsFn() {
		cfgPath, err := securejoin.SecureJoin(root, filepath.Join("containers", containerID, "config.v2.json"))
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(cfgPath))
		if err != nil {
			continue
		}

		var cfg struct {
			Config struct {
				Image string `json:"Image"`
			} `json:"Config"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			slog.Debug("Failed to parse Docker config.v2.json", "path", cfgPath, "error", err)
			continue
		}

		if cfg.Config.Image != "" {
			slog.Debug("Got image ref from Docker config", "image", cfg.Config.Image, "container", containerID)
			return cfg.Config.Image
		}
	}

	return ""
}

var dockerDataRootsFn = dockerDataRoots

func dockerDataRoots() []string {
	roots := []string{"/var/lib/docker"}

	// Check daemon.json for a custom data-root.
	data, err := os.ReadFile("/etc/docker/daemon.json")
	if err == nil {
		var daemonCfg struct {
			DataRoot string `json:"data-root"`
		}
		if json.Unmarshal(data, &daemonCfg) == nil && daemonCfg.DataRoot != "" {
			roots = append([]string{daemonCfg.DataRoot}, roots...)
		}
	}

	return roots
}

// NormalizeImageRef converts Docker Hub short names to fully qualified references.
// e.g., "nginx" → "docker.io/library/nginx"
//
//	"moby/buildkit:tag" → "docker.io/moby/buildkit:tag"
func NormalizeImageRef(ref string) string {
	if ref == "" {
		return ""
	}

	firstSlash := strings.IndexByte(ref, '/')
	if firstSlash == -1 {
		// No slash: "nginx" or "nginx:latest"
		return "docker.io/library/" + ref
	}

	firstComponent := ref[:firstSlash]
	if strings.ContainsAny(firstComponent, ".:") || firstComponent == "localhost" {
		return ref
	}

	// Docker Hub user image: "moby/buildkit:tag" → "docker.io/moby/buildkit:tag"
	return "docker.io/" + ref
}

// FileInfo represents a file entry from the SPDX SBOM with its SHA256 hash.
type FileInfo struct {
	FileName string
	SHA256   string
}

// ParseFiles extracts binary file names and their SHA256 checksums from an SPDX JSON document.
func ParseFiles(sbomData []byte) ([]FileInfo, error) {
	var doc struct {
		Files []struct {
			FileName  string   `json:"fileName"`
			FileTypes []string `json:"fileTypes"`
			Checksums []struct {
				Algorithm     string `json:"algorithm"`
				ChecksumValue string `json:"checksumValue"`
			} `json:"checksums"`
		} `json:"files"`
	}
	if err := json.Unmarshal(sbomData, &doc); err != nil {
		return nil, fmt.Errorf("parsing SPDX document: %w", err)
	}

	var files []FileInfo
	for _, f := range doc.Files {
		if !isBinary(f.FileTypes) && !isScript(f.FileName) {
			continue
		}
		if !isAbsolutePath(f.FileName) {
			slog.Warn("Skipping SBOM file with relative path", "file", f.FileName)
			continue
		}
		for _, c := range f.Checksums {
			if c.Algorithm == "SHA256" {
				files = append(files, FileInfo{
					FileName: f.FileName,
					SHA256:   c.ChecksumValue,
				})
				break
			}
		}
	}
	return files, nil
}

// isAbsolutePath checks that the SBOM filename is a valid absolute path
// (optionally with "./" SPDX prefix) and does not contain ".." traversal
// components.
func isAbsolutePath(name string) bool {
	if name == "" {
		return false
	}

	// Reject any remaining ".." components (Clean resolves most, but
	// e.g. "/../foo" → "/foo" is fine—check the original intent).
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return false
		}
	}

	return true
}

func isBinary(fileTypes []string) bool {
	for _, ft := range fileTypes {
		if ft == "BINARY" {
			return true
		}
	}
	return false
}

// isScript is a simple heuristic that considers files under /bin or /lib paths as possibly scripts, since they may be interpreted (e.g., Python, shell) even if not marked as such in the SBOM (Usually marked as "TEXT").
func isScript(name string) bool {
	return isUnderBinOrLib(name)
}

func isUnderBinOrLib(name string) bool {
	cleaned := filepath.Clean(name)
	parts := strings.Split(cleaned, string(filepath.Separator))
	for _, p := range parts {
		if p == "bin" || p == "lib" || p == "lib64" || p == "sbin" {
			return true
		}
	}
	return false
}

func fetchSPDXSBOM(ctx context.Context, imageRef string) ([]byte, error) {
	repo, err := newAuthenticatedRepo(imageRef)
	if err != nil {
		return nil, fmt.Errorf("creating repository client: %w", err)
	}

	desc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return nil, fmt.Errorf("resolving image %s: %w", imageRef, err)
	}

	return fetchCosignAttestation(ctx, repo, desc)
}

const (
	dsseMediaType        = "application/vnd.dsse.envelope.v1+json"
	spdxPredicateType    = "https://spdx.dev/Document"
	cosignAttTagTemplate = "sha256-%s.att"
)

// fetchCosignAttestation looks for an SPDX SBOM stored as a cosign attestation.
// Cosign uses a tag-based convention: sha256-<hex>.att
func fetchCosignAttestation(ctx context.Context, repo *remote.Repository, imageDesc ocispec.Descriptor) ([]byte, error) {
	digestStr := imageDesc.Digest.String()
	if !strings.HasPrefix(digestStr, "sha256:") {
		return nil, nil
	}
	hex := strings.TrimPrefix(digestStr, "sha256:")
	attTag := fmt.Sprintf(cosignAttTagTemplate, hex)

	slog.Debug("Looking for cosign attestation", "tag", attTag)
	attDesc, err := repo.Resolve(ctx, attTag)
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			slog.Debug("No cosign attestation tag found", "tag", attTag)
			return nil, nil
		}
		return nil, fmt.Errorf("resolving cosign attestation tag %s: %w", attTag, err)
	}

	rc, err := repo.Fetch(ctx, attDesc)
	if err != nil {
		return nil, fmt.Errorf("fetching cosign attestation manifest: %w", err)
	}
	defer func() {
		if err := rc.Close(); err != nil {
			slog.Debug("Failed to close cosign attestation manifest reader", "error", err)
		}
	}()

	manifestBytes, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading cosign attestation manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("parsing cosign attestation manifest: %w", err)
	}

	for _, layer := range manifest.Layers {
		if layer.MediaType != dsseMediaType {
			continue
		}
		predType, ok := layer.Annotations["predicateType"]
		if !ok || predType != spdxPredicateType {
			continue
		}

		return fetchDSSEEnvelope(ctx, repo, layer)
	}

	slog.Debug("Cosign attestation has no SPDX predicate layers")
	return nil, nil
}

func fetchDSSEEnvelope(ctx context.Context, repo *remote.Repository, layer ocispec.Descriptor) ([]byte, error) {
	layerRC, err := repo.Fetch(ctx, layer)
	if err != nil {
		return nil, fmt.Errorf("fetching DSSE envelope: %w", err)
	}
	defer func() {
		if err := layerRC.Close(); err != nil {
			slog.Debug("Failed to close DSSE envelope reader", "error", err)
		}
	}()

	envelopeBytes, err := io.ReadAll(layerRC)
	if err != nil {
		return nil, fmt.Errorf("reading DSSE envelope: %w", err)
	}

	return extractSPDXFromDSSE(envelopeBytes)
}

// extractSPDXFromDSSE extracts the SPDX JSON predicate from a DSSE envelope.
func extractSPDXFromDSSE(envelopeBytes []byte) ([]byte, error) {
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		return nil, fmt.Errorf("parsing DSSE envelope: %w", err)
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding DSSE payload: %w", err)
	}

	var statement struct {
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payloadBytes, &statement); err != nil {
		return nil, fmt.Errorf("parsing in-toto statement: %w", err)
	}

	if statement.PredicateType != spdxPredicateType {
		return nil, fmt.Errorf("unexpected predicate type: %s", statement.PredicateType)
	}

	return []byte(statement.Predicate), nil
}

func newAuthenticatedRepo(imageRef string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(imageRef)
	if err != nil {
		return nil, err
	}

	cfg, err := loadDockerConfig()
	if err != nil {
		slog.Debug("Could not load Docker config, proceeding without auth", "error", err)
		return repo, nil
	}

	repo.Client = &auth.Client{
		Credential: func(ctx context.Context, hostport string) (auth.Credential, error) {
			ac, err := cfg.GetAuthConfig(hostport)
			if err != nil {
				return auth.EmptyCredential, nil
			}
			return auth.Credential{
				Username:     ac.Username,
				Password:     ac.Password,
				RefreshToken: ac.IdentityToken,
				AccessToken:  ac.RegistryToken,
			}, nil
		},
	}
	return repo, nil
}

// loadDockerConfig loads the Docker config from the default location
// ($DOCKER_CONFIG or $HOME/.docker). In Kubernetes, set DOCKER_CONFIG via
// the registryAuth.existingSecret Helm value.
//
// When running under sudo, $HOME is /root which typically doesn't have
// registry credentials. In that case, fall back to the invoking user's
// home directory via $SUDO_USER.
func loadDockerConfig() (*configfile.ConfigFile, error) {
	cfg, err := dockerconfig.Load("")
	if err != nil {
		return nil, err
	}

	if len(cfg.GetAuthConfigs()) > 0 {
		return cfg, nil
	}

	// No auths found — try the original user's config when running under sudo.
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		return cfg, nil
	}

	sudoHome, err := securejoin.SecureJoin("/home", sudoUser)
	if err != nil {
		slog.Debug("Could not resolve home directory for SUDO_USER", "error", err)
		return cfg, nil
	}
	sudoCfg, err := dockerconfig.Load(filepath.Clean(filepath.Join(sudoHome, ".docker")))
	if err != nil {
		slog.Debug("Could not load Docker config for SUDO_USER")
		return cfg, nil
	}

	return sudoCfg, nil
}
