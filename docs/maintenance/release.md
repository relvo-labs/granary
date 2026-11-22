# Docker Hub image release (#39)

Granary is an unofficial fork derived from MinIO, without upstream endorsement.
As of 2026-11-22, **`docker.io/neil0628/granary:v2026.11.22` is public** for
linux/amd64 and linux/arm64, `:latest` points to it, and Helm defaults to that
version. Neil's
2026-11-14 decision in #39 replaces the GHCR proposal with maintainer-host
publishing. Future releases still need qualification and owner go-ahead.
Review the [compatibility exceptions](compatibility.md) before adopting a release.
Helm post-install bucket/user/policy jobs still depend on the unavailable
`quay.io/minio/mc` image
([#33](https://github.com/relvo-labs/granary/issues/33)); image publication
does not make chart provisioning fully working.

## Published releases

### v2026.11.22

Anonymous read-back on **2026-11-22** (empty Docker config) confirmed:

| Field | Value |
| --- | --- |
| Version image | `docker.io/neil0628/granary:v2026.11.22` |
| Alias | `docker.io/neil0628/granary:latest` (same index at read-back) |
| OCI index digest (both tags) | `sha256:93c512d694a2e3ce18cf271bbe17ba4b7c76e5f63e170bc71b6d3587c02caff9` |
| linux/amd64 manifest digest | `sha256:b3cbd66caf6c42978b42ab77a74f44693c4d31b032126c4fef9d6db5a8e85965` |
| linux/arm64 manifest digest | `sha256:0d4b91c8769db0e759d59144e4fb0babc814b38892c1c41fc7d6983dbf2f8785` |
| Source commit | `ca652414fa81d26bea7bb116a3681c5f00cf78b2` (master) |
| Binary banner | `granary version RELEASE.2026-11-22T04-22-56Z.v2026.11.22` |
| Go toolchain | `1.27.4` |

Changes since `v2026.11.14` (security fixes unless noted):

- Authorization uses stored object tags for reads and deletes (#53, PR #65).
- `s3:versionid` comes only from the selected request version (#67, PRs #87/#99).
- OpenID rejects symmetric and mismatched JWT algorithms; HS256/384/512 ID
  tokens are no longer accepted (CVE-2026-33322, #70, PR #76).
- Auto-extract verifies streaming trailers before acknowledging (#66, PR #77).
- S3 Select bounds CSV and JSON Lines record size (CVE-2026-39414, #73, PR #81;
  #79, PR #89).
- Storage confines `ReadMultiple` paths and grid RPC volume/path arguments
  (CVE-2026-42600, #74, PR #83; #82, PRs #92/#100). Linux only; Windows path
  semantics are tracked in #98.
- Replication SSE headers are accepted only from replication requests
  (CVE-2026-34204, #72, PR #86).
- LDAP STS returns uniform auth errors and throttles failed logins
  (CVE-2026-33419, #71, PR #93).
- Fix: replication proxy ignores skipped targets for tag reads (#52, PR #63).

Qualification: the 13 canonical local gates (including full tagged tests,
lint and vulncheck) passed on a tree identical to the source commit; both
platform binaries were run with `--version` and no network. No multi-node or
live-server end-to-end test was run.

### v2026.11.14

Anonymous read-back on **2026-11-15** confirmed the public Docker Hub
repository and these references for the first image release:

| Field | Value |
| --- | --- |
| Version image | `docker.io/neil0628/granary:v2026.11.14` |
| Alias | `latest` pointed here until `v2026.11.22` |
| OCI index digest | `sha256:f3eba4c294bb5a445060f6ff7abb7a13e903cb19e7d54c27ad205fd2fa0052e0` |
| linux/amd64 manifest digest | `sha256:96b485ae28c54501da18c14613b84618cf33361a7b2e6c00815e46833cf1c9d1` |
| linux/arm64 manifest digest | `sha256:94bf28c58cb074cdc4827f1994b7299fd31a2c82d1b272c98e5b67434d22f961` |
| Source commit | `6ca7f2eabe5f8b5c83fab537f9d23212a6c81165` (master; includes PR #50 and PR #51) |
| Binary banner | `granary version RELEASE.2026-11-14T17-23-08Z.v2026.11.14` |
| Go toolchain | `1.27.4` |

No git tag or GitHub Release was created. Use the version tag and index digest
for repeatable pulls; `latest` can move with future releases.

## Prerequisites and source identity

Use a Linux maintainer host with Bash, Git, Python 3, curl, tar, timeout, Docker Engine,
buildx and the exact Go toolchain in go.mod. The host must execute linux/amd64
and linux/arm64 containers, using binfmt/QEMU for its non-native architecture.
The script executes both actual Granary binaries; advertised buildx platform
support alone does not pass verification. Allow enough disk, memory and time
for two Go builds (the Dockerfile currently sets GOMAXPROCS=8).

The checkout must be clean, including untracked files. HEAD must equal the
optional `--commit` full SHA (otherwise the script selects current HEAD).
The script verifies that origin is exactly
`https://github.com/relvo-labs/granary.git` and freshly fetches master from that
explicit URL, including full history in shallow
clones, and requires HEAD to be an ancestor of or equal to that ref. This lets
the owner qualify a fixed master commit while master advances. An unmerged
feature branch is rejected, including when selected for manual Actions.
In `--push` mode, when `latest` exists, HEAD must also be a descendant of or
equal to its `org.opencontainers.image.revision`. Both platform revisions and version labels
must agree. The labels are read with the publisher's Docker context from the
resolved immutable `latest` digest; missing or malformed labels abort.
Build context comes from `git archive` of that exact commit, excluding ignored
local files. No branch switch, git tag or GitHub Release is made by the script.

VERSION must be a real calendar date in `vYYYY.MM.DD` form within today UTC
plus or minus one day. For `--push`, `docker buildx imagetools inspect` uses
the publisher's Docker context to check the candidate tag and `latest`; only an explicit
manifest-unknown or reference-specific not-found response establishes absence.
Authentication, network and unknown failures abort. An anonymous Docker Hub
API 404 never substitutes for this check, because it can hide private tags.
VERSION must be newer than the authenticated `latest` version and every tag
in the anonymous tag listing. All tag pages must return HTTP 200, including
before the first release; a 404 aborts even when candidate and `latest` are
explicitly absent. Two missing references do not establish that a private
repository has no other version tags. These tag, version and revision checks
run before any build and repeat just before pushing.

Run only one publisher at a time. Hub manifest writes have no atomic
create-if-absent operation; these checks cannot prevent another publisher
racing between the last check and push. The owner must serialize publication
and protect version tags against writes by other publishers. Never overwrite
an existing version tag, even to recover a failed release.

## Version mapping

`vYYYY.MM.DD` is the image tag and OCI `version` label, not a timestamp passed
as `cmd.Version`. `gen-ldflags.go` expects a UTC RFC3339 timestamp and derives
`PREFIX.YYYY-MM-DDTHH-MM-SSZ[.SUFFIX]` as its binary release tag. The script
passes the commit's UTC committer time as `COMMIT_TIME`, the full HEAD SHA as
`COMMIT_ID`, `MINIO_RELEASE=RELEASE` and `MINIO_HOTFIX=vYYYY.MM.DD`.
For example, commit time `2026-11-14T10:04:42Z` and image `v2026.11.15` produce
`RELEASE.2026-11-14T10-04-42Z.v2026.11.15` in `granary --version`.

`cmd.Version` remains the commit timestamp, preserving `make build` and the
Unix timestamp used by `xl.meta`'s `WrittenByVersion`. The release script checks
the generator's exit and essential flags directly, avoiding Make's silent
empty-LDFLAGS failure (#38). Both platform banners must then report the exact
release tag, full commit and matching runtime architecture. OCI `created` is
the same deterministic commit time; revision is the full commit. Source, title
and description identify this unofficial MinIO-derived fork. The release
license label is `AGPL-3.0-or-later`, following LICENSE and the source notices'
“version 3 ... or ... any later version” grant. Attribution files are retained.

## Dry run

On the selected clean master commit, with a date within today UTC plus or
minus one day:

```sh
make release-image VERSION=v2026.11.15
# Equivalent, with an optional exact source check:
bash buildscripts/release-image.sh --dry-run --commit "$(git rev-parse HEAD)" v2026.11.15
```

The default is dry run. It creates a task-scoped docker-container buildx
builder with `--driver-opt image=moby/buildkit@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe`,
builds and locally loads each platform, and runs `granary --version`
without network access or storage mounts. Cleanup removes only its own local
image tags and builder, including that builder's cache; it never prunes globally.
Each Docker cleanup command has a 30-second timeout and 5-second kill grace;
failure of one removal does not skip the others. Cleanup ignores further INT
and TERM signals and preserves the original failure or interruption status.
The BuildKit pin is the multi-arch index resolved on 2026-11-14 with an empty
Docker config using `docker buildx imagetools inspect docker.io/moby/buildkit:buildx-stable-1`.
Dry-run mode builds and verifies both platforms and their version stamps and
applies the OCI labels. It performs no release-tag existence, newest-version
or published-revision checks and needs no publisher credentials; an already
published date can be used. The build still pulls its public base and BuildKit
images. No registry login or push occurs. An interruption that bypasses traps
(such as SIGKILL) may require removing the printed task builder and its image tags by
their exact names. Never use global prune for cleanup.

`release-dryrun.yml` is manual-only with no inputs or secrets, read-only token
permissions and pinned actions. Select master for the dispatch; it uses the
current UTC date as VERSION. It registers
QEMU on the disposable GitHub runner with a Docker Hub binfmt index pinned by
digest (read anonymously on 2026-11-14), then calls the same dry-run Make target.
Docker buildx is supplied by the runner and checked before use. No hosted run
is claimed by this runbook; the published image record above documents the
maintainer-host result.

## Publish and read back (owner-authorized maintainer host only)

Docker Hub credentials must already be configured on the host, outside the
checkout. Before the first release, **create the `neil0628/granary` repository
in Docker Hub and set its visibility to public**. The repository must already
exist and its tag list must be anonymously readable before any publishing
build begins, including for the first release. Check its public visibility
before each publication. Set `DOCKER_CONFIG` to
that host-local directory if necessary. The
script never logs in, reads credential files or prints credential values, and
does not send them into the build context or Actions. Do not enable shell
tracing or record credentials in evidence. After owner go-ahead, use the same
qualified clean source and date:

```sh
bash buildscripts/release-image.sh --push --commit "$(git rev-parse HEAD)" v2026.11.15
```

After both local architecture checks pass, the script builds the multi-arch
index from the same source and cached layers and pushes `:v2026.11.15` and
`:latest`. `--metadata-file` captures `containerimage.digest` from the push.
The version tag must then be readable through both the anonymous Hub API
and a buildx manifest inspect with a fresh empty Docker config. A failed
anonymous read aborts with an instruction to set the repository public.
The script reads back both tags with `docker buildx imagetools inspect`,
requires both linux/amd64 and linux/arm64 in each manifest, and compares both
index digests and the anonymous digest with the captured pushed digest.
Missing metadata or any mismatch fails. Independent read-back commands are:

```sh
docker buildx imagetools inspect docker.io/neil0628/granary:v2026.11.15
docker buildx imagetools inspect docker.io/neil0628/granary:latest
```

Keep command exits, both version banners, source SHA, version and final digest
as private local evidence outside the checkout. If a push or read-back fails,
stop and inspect both remote tags: publication is not transactional. Preserve
any version tag that exists; ask the owner to approve recovery of `latest`
against the verified digest instead of rerunning or replacing a version tag.
After each successful release, prepare a separately reviewed docs/Helm update
with the published version/digest and add its source and read-back record above.
Git tags and release notes, if desired, remain separate owner-authorized work.
