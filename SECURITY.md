# Security policy

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on the repository hosting this
collection: open its **Security** tab, select **Advisories**, then **Report a
vulnerability**. Do not use public issues or pull requests to disclose exploitable
details, credentials, private artifacts, or operational payloads.

This local collection has no configured hosting repository URL. Repository
maintainers must enable private vulnerability reporting before publication.
If the reporting button is unavailable, do not assume a private channel exists:
request a private reporting route from the maintainer without disclosing details.
No response-time or remediation SLA is promised by this policy.

Provide, where safe:

- Affected skill/helper, version or commit, and relevant file locations.
- Expected and observed behavior, prerequisites, and potential impact.
- A minimal inert reproduction or synthetic fixture, with secrets redacted.
- Suggested mitigation and whether any disclosure has already occurred.

Do not upload live malware, private repository contents, or working credentials.
Obtain authorization before testing any system you do not own.

## Scope

Relevant reports include target execution/imports during static collection,
path/symlink escapes, unsafe special-file access, unintended network activity,
resource-limit bypasses, sensitive-output disclosure, and instruction-boundary
failures that lead to unauthorized actions.

False positives, missing analysis coverage, and unsupported conclusions are also
important. Use a public issue only when the example is safe to disclose and does
not reveal an exploitable flaw or private data.

There is no release-specific support matrix yet. Report the affected revision;
historical revisions are not guaranteed fixes or ongoing support.

## Operational limitations

Skill instructions are not a sandbox. Helpers are static evidence collectors,
not malware runners or secret redactors. Read-only collection can update access
times, cannot guarantee a stable live snapshot, and cannot reliably identify
same-device bind mounts. Prefer operator-supplied read-only snapshots.

Decoded previews are opt-in and may expose secrets. Reports and metadata must
remain local and outside the reviewed target. No findings is not proof of safety.
See the [skill safety reference](malicious-intent-analysis/references/safety-and-escalation.md)
for the full boundaries and dynamic-analysis handoff requirements.
