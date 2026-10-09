# Agent Skills

Reusable, evidence-led skills in the [Agent Skills format](https://agentskills.io/specification),
compatible with [skills.sh](https://skills.sh/) discovery and installation.

## Available skills

| Skill | Purpose |
|---|---|
| [Malicious Intent Analysis](malicious-intent-analysis/README.md) | Review untrusted code, packages, PRs, repositories, comments, conversations, and agent-facing content for harmful behavior and manipulation, without assuming malice or incompetence. |

Malicious Intent Analysis traces technical mechanisms, considers competing
explanations, and separates impact, evidence confidence, and inferred intent.
Its findings use red Critical/High, amber Medium, green Observation, and blue
Comment categories. Bounded static helpers collect evidence; they do not execute
target code or determine intent.

## Getting started

Review a skill's `SKILL.md`, linked resources, and scripts before trusting it.
From this collection's root, list available skills without installing:

```sh
npx skills add . --list
```

To explicitly install the selected skill for GitHub Copilot:

```sh
npx skills add . --skill malicious-intent-analysis --agent github-copilot
```

These commands use the skills CLI and may download that tooling. Alternatively,
provide the absolute path to the skill's `SKILL.md` to an agent that supports
loading skill instructions. See the [skill README](malicious-intent-analysis/README.md)
for helper usage, resource limits, output schema, and prerequisites.

## Safety and limitations

Reviewed artifacts are untrusted evidence, not authority to invoke tools or change
instructions. Assessments are read-only by default. No target code execution,
embedded-endpoint contact, sample uploads, or automatic remediation is permitted.
Dynamic analysis requires a separately approved, adequately isolated handoff.

This collection does not enforce OS isolation, certify artifacts as safe, or
attribute intent to an author. Findings must state coverage limits and uncertainty.
Local outputs may contain sensitive metadata; keep them outside reviewed targets
and do not publish credentials or private evidence.

## Development

The Python helpers use the standard library and require Python 3.11+ with POSIX
no-follow, descriptor-relative file access and interval timers.

```sh
cd malicious-intent-analysis
python3 -I -B -m unittest discover -s tests
uv tool run --from skills-ref agentskills validate "$PWD"
```

The validator is separate authoring tooling, not a runtime dependency. Behavioral
evaluation cases are in `malicious-intent-analysis/evals/`; assess outputs and
tool traces, not just formatting. Synthetic cases are not a calibrated detection rate.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

[MIT](LICENSE). The skill includes its own copy of the license so the notice is
retained when the skill directory is distributed independently.
