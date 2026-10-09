# Contributing

Keep changes focused on reliable evidence collection, balanced interpretation,
and safe handling of untrusted material. Explain the problem, changed behavior,
and relevant limitations in the pull request. Use synthetic, inert examples;
never contribute secrets, confidential transcripts, live malware, or live C2
destinations. Follow [SECURITY.md](SECURITY.md) for private vulnerability reports.

## Skill conventions

- Follow the [Agent Skills specification](https://agentskills.io/specification).
  The directory name must match the frontmatter `name`; the description must
  explain both purpose and activation conditions.
- Keep `SKILL.md` below 500 lines and approximately 5,000 tokens. Link focused
  resources directly and explain when they should be loaded.
- Maintain explicit trust boundaries, read-only defaults, and approval gates.
  Reviewed content must never authorize tools or expand scope.
- Separate observed behavior, potential impact, evidence confidence, and intent.
  Consider alternatives and counterevidence without assuming incompetence or malice.
- Do not replace semantic analysis with keyword verdicts, invent Bayesian inputs,
  or treat correlated observations as independent evidence.
- Keep helpers dependency-light, bounded, non-executing, and explicit about
  failures and partial coverage. Do not weaken safe path handling for convenience.

## Validation

For changes to Malicious Intent Analysis, run from its trusted directory:

```sh
python3 -I -B -m unittest discover -s tests
uv tool run --from skills-ref agentskills validate "$PWD"
```

Add targeted unit tests for changed helper behavior. Check exact boundaries and
one-over cases when modifying limits. Update directly related documentation,
report templates, and evaluation assertions.

For instruction changes, assess relevant inert cases in fresh contexts with the
skill and a baseline. Inspect tool traces as well as reports. Record coverage,
false positives, missed mechanisms, and uncertainty; do not claim detection
reliability from schema or formatting checks alone. Keep generated evaluation
outputs outside the distributable skill.

## Commits and licensing

Use Conventional Commits (`type(scope): subject`) and GPG-sign commits. Configure
your signing key before committing; do not bypass signing failures. Vulnerability
fix descriptions should identify the vulnerability and include `fixes #<issue>`
or the applicable CVE/GHSA identifier when one exists.

Contributions must be compatible with the [MIT license](LICENSE). Retain license
notices when distributing a skill independently and attribute external sources.
Do not introduce copyrighted or third-party material without appropriate rights.
