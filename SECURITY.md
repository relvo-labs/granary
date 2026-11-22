# Security policy for Granary (unofficial MinIO fork)

Granary ([relvo-labs/granary](https://github.com/relvo-labs/granary)) is an
independent, **unofficial fork** of MinIO, not affiliated with or endorsed by
MinIO, Inc. This policy concerns this fork's source and dependencies.

## Maintenance scope

The fork focuses on source maintenance, dependency security, CI and
compatibility. As of **2026-11-22**, the latest image release is
`docker.io/neil0628/granary:v2026.11.22`; there are no GitHub releases and no
published supported-version matrix. Fixes land on the default branch and reach
users in the next `vYYYY.MM.DD` image release; older image tags are not patched.
Upstream MinIO releases and images do not establish a supported fork version.
There is no guaranteed response time, fix schedule or enterprise support SLA.
The [CI runbook](docs/maintenance/ci.md) records validation boundaries;
successful local checks do not certify production security.

## Supported platforms

Only Linux builds are in scope for security support, including the published
`docker.io/neil0628/granary` images for linux/amd64 and linux/arm64. Other
platforms, such as Windows, can be built from source but are outside security
support. Storage path confinement does not apply Windows path rules, such as
`\` separators and UNC paths; see
[issue #98](https://github.com/relvo-labs/granary/issues/98).

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub private vulnerability
reporting: open
[Security → Report a vulnerability](https://github.com/relvo-labs/granary/security/advisories/new)
in this repository. Reports remain private under GitHub's security advisory
permissions until publication.

Do **not** post undisclosed exploit details, credentials, logs containing
personal data, or real host/customer details in public issues, pull requests
or comments.

Inherited upstream email addresses, Slack and vendor policies are not this
fork's security reporting channels. Do not send fork findings to
`security@min.io`.

## Preparing information

The [vulnerability report guidance](VULNERABILITY_REPORT.md) describes what a
useful report contains. For ordinary non-sensitive bugs, use the fork issue
tracker with a synthetic reproduction and exact source commit; follow
[CONTRIBUTING.md](CONTRIBUTING.md).
