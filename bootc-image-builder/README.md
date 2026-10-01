# bootc-image-builder

`bootc-image-builder` is the compatibility CLI for building disk images from
[bootc](https://github.com/containers/bootc) bootable containers. The formerly
standalone implementation has merged into [`image-builder`](../README.md).

There is now one multicall binary with two command-line interfaces:

- Invoked as `image-builder`, it supports both package-based and bootable container
  builds. Use `image-builder build --bootc-ref ... <image-type>` for bootc inputs.
- Invoked as `bootc-image-builder`, it selects the compatibility interface, using
  a positional container reference and `--type`. The `build` subcommand is
  optional in this mode.

Compatibility with the old standalone tool is not exact. **New and migrated
workflows should use `image-builder` directly**, either installed on the host or
in the `ghcr.io/osbuild/image-builder-cli` container.

## Documentation

The maintained documentation lives with `image-builder`:

- [Migrating from `bootc-image-builder`](../doc/20-advanced/20-bootc/50-migration.md):
  host and container examples, flag mappings, and image type changes.
- [Building from bootable containers](../doc/01-usage.md#bootc): source, build, and
  installer payload references, filesystem selection, and kernel arguments.
- [Sources of configuration](../doc/20-advanced/20-bootc/05-sources-of-configuration.md):
  configuration embedded in the source container, disk layouts, and variants.
- [ISOs](../doc/20-advanced/20-bootc/10-isos.md): the recommended `bootc-generic-iso`
  workflow and offline installer payloads.
- [Blueprint reference](https://osbuild.org/docs/user-guide/blueprint-reference/):
  user, filesystem, and other customizations. Check the **bootc** tab for support.

## Running the compatibility container

The `quay.io/centos-bootc/bootc-image-builder:latest` compatibility container is
maintained in the [bootc-image-builder repository](https://github.com/osbuild/bootc-image-builder).
That repository is active again, with Quay container builds resuming. The
container packages the multicall binary from `image-builder` and invokes it as
`/usr/bin/bootc-image-builder` by default. It is intended for existing workflows
that still require the compatibility CLI.
For host-installed builds, use `image-builder` rather than compatibility mode.

Install [Podman](https://podman.io/) and run the compatibility container rootful
and privileged. On SELinux-enforcing hosts, install `osbuild-selinux` or the
equivalent osbuild SELinux policies. On macOS or Windows, the Podman machine
must be rootful (`podman machine set --rootful` while the machine is stopped).

Base bootc images may not include a user. For this example, create `config.toml`
with a user and replace the placeholder with your public SSH key:

```toml
[[customizations.user]]
name = "alice"
key = "ssh-ed25519 AAA... user@example.com"
groups = ["wheel"]
```

Then pull the source container into rootful Podman's storage and build a QCOW2
image:

```console
$ sudo podman pull quay.io/centos-bootc/centos-bootc:stream9
$ mkdir -p output
$ sudo podman run \
    --rm \
    -it \
    --privileged \
    --pull=newer \
    --security-opt label=type:unconfined_t \
    -v ./config.toml:/config.toml:ro \
    -v ./output:/output \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest \
    --type qcow2 \
    --rootfs ext4 \
    quay.io/centos-bootc/centos-bootc:stream9
```

The disk is written to `output/qcow2/disk.qcow2`. Membership in `wheel` alone does
not enable passwordless sudo; configure a user password in the blueprint or
sudo policy in your derived container if needed.

## Compatibility details

Use `bootc-image-builder build --help` for the current build flags, rather than
help output copied from the old standalone tool. In the compatibility container:

```console
$ sudo podman run --rm quay.io/centos-bootc/bootc-image-builder:latest build --help
```

Keep these differences in mind:

- Compatibility builds require rootful Podman. The old rootless `--in-vm`
  example no longer applies: compatibility mode has no `--in-vm` flag. The
  `image-builder build` CLI still provides `--in-vm`.
- Librepo is enabled by default; `--use-librepo=True` is unnecessary.
- Compatibility mode picks up `/config.toml` or `/config.json` implicitly. Mount
  only one of these files. The `image-builder` CLI instead requires an explicit
  `--blueprint` argument.
- The compatibility installer payload flag is `--installer-payload-ref`, not
  `--bootc-installer-payload-ref`. The latter belongs to the `image-builder` CLI.
- `anaconda-iso` and its `iso` alias remain legacy compatibility image types;
  they are not supported by the `image-builder` CLI. For new ISO workflows, use
  `image-builder build ... bootc-generic-iso` and follow the [ISO documentation](../doc/20-advanced/20-bootc/10-isos.md).
  `bootc-installer` is still available but is not recommended.
- Multiple disk types can still be requested with repeated `--type` flags (for
  example, `--type qcow2 --type raw`). Do not mix disk and ISO types. The
  `image-builder build` CLI builds one type per invocation and uses different
  artifact filenames and output directory layouts.
- Use `/usr/lib/image-builder/bootc` for configuration embedded in source
  containers. `/usr/lib/bootc-image-builder` is a legacy fallback, not the
  location to use for new containers. See [sources of configuration](../doc/20-advanced/20-bootc/05-sources-of-configuration.md)
  for precedence rules.

## Building the compatibility container locally

This repository also has a Containerfile for local compatibility builds. Run
this from the root of the `image-builder` repository, not this subdirectory:

```console
$ sudo podman build -f bootc-image-builder/Containerfile -t localhost/bootc-image-builder .
```
