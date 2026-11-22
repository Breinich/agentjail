# Images

`images/base/Containerfile` is the jail base image: a pinned Debian slim base,
Node, Python, git, ripgrep, and an unprivileged `agent` user (uid/gid 10000).
It contains no agentjail code, no credentials, and no jail state.

Build it locally with rootless podman:

```sh
podman build -f images/base/Containerfile -t localhost/agentjail-base:1 images/base
podman image inspect --format '{{.Digest}}' localhost/agentjail-base:1
```

Paste the printed digest into a profile's `image.digest`. The tag is a label;
the digest is the pin the launcher checks.

Building is not required to validate profiles, and increment 1 does not publish
an image. Measured on the development host (rootless podman 6.1.3, Fedora 45):
about 22 s for a warm base layer, 448 MB on disk, and a final image that runs as
uid 10000 with Node 24, Python 3.11, git, and ripgrep. Python inside the image
is the Debian bookworm default (3.11); the `agentjail` CLI itself needs Python
3.12+ and runs on the host, not in the jail.

## How to add a runtime

A runtime (an agent CLI, a language toolchain, an SDK) is added as its own
image that derives from the base, or as a small layer on top of it. Do not add
it by bind-mounting a host install into a jail: FUSE-backed paths such as
AppImage mounts cannot be bind-mounted at all (`crun: cannot stat self/fd/N:
Permission denied`), and a host install usually drags in host configuration.

1. Create a directory per runtime, for example `images/<runtime>/`.
2. Add a `Containerfile` whose `FROM` is the base image **pinned by digest**:

   ```dockerfile
   FROM localhost/agentjail-base@sha256:<digest-of-the-base-you-built>
   USER root
   RUN <install the runtime without secrets, without postinstall scripts where possible>
   USER 10000:10000
   WORKDIR /work
   ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/agentjail-entrypoint"]
   ```

   Installing as root is fine at build time; the final `USER 10000:10000` is
   not optional.
3. Build it, then reference it from a profile by digest:

   ```sh
   podman build -f images/<runtime>/Containerfile -t localhost/agentjail-<runtime>:1 images/<runtime>
   ```

4. Keep the runtime's cache and config under `$HOME` (`/home/agent`) or a
   declared `resources.tmpfs` path, so nothing the agent writes ends up on a
   read-only mount.

Rules that CI enforces for every `images/**/Containerfile`
(`scripts/check_containerfile.py`):

- every `FROM` is pinned with `@sha256:<64 hex>`;
- the final stage sets a non-root `USER`;
- no `ENV` line names a credential;
- no `ADD` from a URL;
- an `ENTRYPOINT` or `CMD` is present.

CI also attempts a real build of `images/base` as a separate, non-blocking job,
because apt and npm mirrors are an external dependency.
