# Compatibility exceptions

Granary is an unofficial fork derived from MinIO. The following exceptions
apply to inherited S3 behavior.

## Proxy-injected SigV4 headers

Since issue #25, SigV4
requests carrying unsigned `x-amz-*` headers, such as CloudFront's injected
`X-Amz-Cf-Id`, are rejected with HTTP 400. Such deployments must strip the
header at the proxy or use a configuration that does not inject it. This
behavior is not relaxed by an allowlist.

## Proxied DeleteObjectTagging

Since [PR #51](https://github.com/relvo-labs/granary/pull/51), a
`DeleteObjectTagging` request proxied to replication targets first reads the
remote tags for authorization. The replication target credentials must also
have `s3:GetObjectTagging` permission, in addition to the permission needed
to delete tags.

With multiple targets, any target's tag-read error other than a missing
object/version (`NoSuchKey` or `NoSuchVersion`), including HTTP 403 or 5xx,
fails the whole delete before tags are removed. This is intentional
fail-closed behavior; previously, one successful proxied delete sufficed.
Review target credential policies and target availability when upgrading.
See [issue #54](https://github.com/relvo-labs/granary/issues/54) for the
compatibility follow-up.
