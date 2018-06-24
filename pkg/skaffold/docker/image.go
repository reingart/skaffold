/*
Copyright 2018 The Skaffold Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package docker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/progress"
	"github.com/docker/docker/pkg/streamformatter"
	"github.com/docker/docker/pkg/term"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// RunBuild performs a docker build and returns nothing
func RunBuild(ctx context.Context, out io.Writer, cli APIClient, workspace string, opts types.ImageBuildOptions) error {
	logrus.Debugf("Running docker build: context: %s, dockerfile: %s", workspace, opts.Dockerfile)

	// Add a sanity check to check if the dockerfile exists before running the build
	if _, err := os.Stat(filepath.Join(workspace, opts.Dockerfile)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("Could not find dockerfile: %s", opts.Dockerfile)
		}
		return errors.Wrap(err, "stat dockerfile")
	}

	// Like `docker build`, we ignore the errors
	// See https://github.com/docker/cli/blob/75c1bb1f33d7cedbaf48404597d5bf9818199480/cli/command/image/build.go#L364
	authConfigs, _ := DefaultAuthHelper.GetAllAuthConfigs()
	opts.AuthConfigs = authConfigs

	buildCtx, buildCtxWriter := io.Pipe()
	go func() {
		err := CreateDockerTarContext(buildCtxWriter, opts.Dockerfile, workspace)
		if err != nil {
			buildCtxWriter.CloseWithError(errors.Wrap(err, "creating docker context"))
			return
		}
		buildCtxWriter.Close()
	}()

	progressOutput := streamformatter.NewProgressOutput(out)
	body := progress.NewProgressReader(buildCtx, progressOutput, 0, "", "Sending build context to Docker daemon")

	resp, err := cli.ImageBuild(ctx, body, opts)
	if err != nil {
		return errors.Wrap(err, "docker build")
	}
	defer resp.Body.Close()
	return StreamDockerMessages(out, resp.Body)
}

// StreamDockerMessages streams formatted json output from the docker daemon
// TODO(@r2d4): Make this output much better, this is the bare minimum
func StreamDockerMessages(dst io.Writer, src io.Reader) error {
	fd, _ := term.GetFdInfo(dst)
	return jsonmessage.DisplayJSONMessagesStream(src, dst, fd, false, nil)
}

func RunPush(ctx context.Context, cli APIClient, ref string, out io.Writer) error {
	registryAuth, err := encodedRegistryAuth(ctx, cli, DefaultAuthHelper, ref)
	if err != nil {
		return errors.Wrapf(err, "getting auth config for %s", ref)
	}
	rc, err := cli.ImagePush(ctx, ref, types.ImagePushOptions{
		RegistryAuth: registryAuth,
	})
	if err != nil {
		return errors.Wrap(err, "pushing image to repository")
	}
	defer rc.Close()
	return StreamDockerMessages(out, rc)
}

func AddTag(src, target string) error {
	srcRef, err := name.ParseReference(src, name.WeakValidation)
	if err != nil {
		return errors.Wrap(err, "getting source reference")
	}

	auth, err := authn.DefaultKeychain.Resolve(srcRef.Context().Registry)
	if err != nil {
		return err
	}

	targetRef, err := name.ParseReference(target, name.WeakValidation)
	if err != nil {
		return errors.Wrap(err, "getting target reference")
	}

	return addTag(srcRef, targetRef, auth, http.DefaultTransport)
}

func addTag(ref name.Reference, targetRef name.Reference, auth authn.Authenticator, t http.RoundTripper) error {
	tr, err := transport.New(ref.Context().Registry, auth, t, []string{targetRef.Scope(transport.PushScope)})
	if err != nil {
		return err
	}

	img, err := remote.Image(ref, auth, tr)
	if err != nil {
		return err
	}

	return remote.Write(targetRef, img, auth, t, remote.WriteOptions{})
}

// Digest returns the image digest for a corresponding reference.
// The digest is of the form
// sha256:<image_id>
func Digest(ctx context.Context, cli APIClient, ref string) (string, error) {
	args := filters.KeyValuePair{Key: "reference", Value: ref}
	filters := filters.NewArgs(args)
	imageList, err := cli.ImageList(ctx, types.ImageListOptions{
		Filters: filters,
	})
	if err != nil {
		return "", errors.Wrap(err, "getting image id")
	}
	for _, image := range imageList {
		for _, tag := range image.RepoTags {
			if tag == ref {
				return image.ID, nil
			}
		}
	}
	return "", nil
}

func remoteImage(identifier string) (v1.Image, error) {
	ref, err := name.ParseReference(identifier, name.WeakValidation)
	if err != nil {
		return nil, errors.Wrap(err, "parsing initial ref")
	}

	auth, err := authn.DefaultKeychain.Resolve(ref.Context().Registry)
	if err != nil {
		return nil, errors.Wrap(err, "getting default keychain auth")
	}

	return remote.Image(ref, auth, http.DefaultTransport)
}

func RemoteDigest(identifier string) (string, error) {
	img, err := remoteImage(identifier)
	if err != nil {
		return "", errors.Wrap(err, "getting image")
	}

	h, err := img.Digest()
	if err != nil {
		return "", errors.Wrap(err, "getting digest")
	}

	return h.String(), nil
}
