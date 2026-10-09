# Malicious Intent Analysis

An evidence-led [Agent Skills](https://agentskills.io/specification) skill for
reviewing untrusted code, packages, PRs, repositories, comments, conversations,
and LLM-facing content. It traces mechanisms rather than declaring intent from
keywords, and considers mistakes without assuming incompetence.

Read [SKILL.md](SKILL.md) for activation and workflow. Reports distinguish impact,
confidence, and intent: red Critical/High, amber Medium, green Observation, blue
Comment. This is neither a universal malware scanner nor a safety certificate.

## Use and installation

Ask an agent to use this directory's `SKILL.md` for a read-only assessment.
Review the skill itself before installation. Local discovery without installation:

```sh
npx skills add /home/rslater/skills --list
```

Explicit installation for a chosen supported agent, if desired:

```sh
npx skills add /home/rslater/skills --skill malicious-intent-analysis --agent github-copilot
```

Installation is not performed by the skill. skills.sh provides discovery/install
tooling; Agent Skills defines the format. The skill is [MIT licensed](LICENSE);
retain its notice when redistributing. No public hosting repository is assumed.

## Static helpers

Python 3.11+, POSIX descriptor-relative no-follow access and interval timers are
required. No third-party runtime dependencies. Use a trusted working directory
and the absolute installed script path, with Python isolated mode:

```sh
python3 -I /home/rslater/skills/malicious-intent-analysis/scripts/inspect_artifact.py --root /absolute/target inventory
python3 -I /home/rslater/skills/malicious-intent-analysis/scripts/inspect_artifact.py --root /absolute/target unicode relative/file.txt
python3 -I /home/rslater/skills/malicious-intent-analysis/scripts/inspect_artifact.py --root /absolute/target decode --encoding base64 --encoding hex relative/file.txt
```

Decoding supports explicit Base64, hex, and URL-percent transforms in order.
No execution, imports, network, archive extraction or decompression occurs.
Base64 permits whitespace; hex permits outer whitespace only. Percent decoding
requires ASCII input and valid percent escapes; `+` is literal, not form-space.

Limits can only be lowered using options before the subcommand: `--entries`,
`--file-bytes`, `--total-bytes`, `--layers`, `--decoded-bytes`, `--seconds`.
Defaults are 10,000 encountered entries, 5 MiB/file, 100 MiB input, three layers,
5 MiB cumulative decoded output/artifact, and 60 seconds. Directories count toward
entries to bound traversal. Individual-file commands are bounded by bytes/deadline;
entry counting applies to inventory. No links, special files, multiply linked
regular files or cross-device traversal. Same-device bind mounts are a known
limitation. Prefer trusted read-only snapshots; reads can change access times.

`--preview` on decode opts into at most 256 decoded bytes rendered as escaped JSON.
It is **not a secret redactor**. Default outputs omit source/decoded text.
Unicode analysis reports UTF-8 byte offsets, 1-based lines/character columns,
and code-point names for format controls and non-whitespace C0/C1 controls.
At most 256 occurrences are detailed; total count is retained. Mixed scripts are
not automatically suspicious.

## Output contract

JSON schema version 1:

| Field | Meaning |
|---|---|
| `coverage` | `complete`, `partial`, or `failed`; collection only, not semantic assurance. |
| `limits` | Effective resource limits. Present once a collector is initialized. |
| `entries_encountered`, `input_bytes_read` | Enumeration and actual read counts, including unsuccessful reads. |
| `items` | Inspected/skipped paths with explicit reasons; full reads may have SHA-256 and byte count. |
| `diagnostics`, `error` | Coverage caveats and explicit fatal/limit errors. |
| `transforms` | Ordered encoding, input/output SHA-256 and output byte size for successful decoding. |

No full-file digest is attached to partial or changed reads. Failed transforms
report errors rather than empty success. Inventory may report non-UTF-8/binary
digests without claiming semantic interpretation. Unicode undecodability and
truncated occurrence detail are partial coverage.

Exit codes: **0** complete collection, **1** partial/limited, **2** fatal/request
error. Invalid CLI syntax uses argparse's exit 2 and stderr usage message.
Errors after initialization retain available collection metadata.
Escape evidence again when placing it in Markdown; JSON escaping is not Markdown
escaping. Redact secrets, defang indicators, and keep outputs local/outside target.

## Validation and evaluation

From this trusted skill directory:

```sh
python3 -I -B -m unittest discover -s tests
uv tool run --from skills-ref agentskills validate "$PWD"
```

`skills-ref` is a separate optional authoring validator, not a runtime dependency.
The current PyPI distribution exposes `agentskills`, although the specification
documents `skills-ref validate`. Pass an absolute directory: this validator
incorrectly treats literal `.` as an empty directory name. The command above
provisions it in uv's isolated tool environment; use an already trusted validator
when available.

`evals/evals.json` defines ten independent inert cases in a shared scenario file,
with expected results and assertions. A clean-context batch compares skill-guided
and baseline assessments, checking report content and tool traces. For stronger
isolation, run each prompt in a separate session. Keep outputs outside this
package; do not treat a small synthetic evaluation as a calibrated detection rate.

Sources: [format](https://agentskills.io/specification),
[creation practices](https://agentskills.io/skill-creation/best-practices),
[evaluation](https://agentskills.io/skill-creation/evaluating-skills),
[skills CLI](https://github.com/vercel-labs/skills).
