# Technical analysis

Reconstruct entry, activation, sources, transforms, boundaries, sinks and impact.
Cite each link; distinguish observed, statically inferred and unresolved behavior.
Search is triage, not reachability analysis. Use safe existing call/symbol
intelligence or inspect callers/callees manually without target plugins or builds.

## Code, pull requests and packages

Inspect changed and relevant unchanged paths: lifecycle/import hooks, CI, plugin
registration, background tasks, sensitive sources, execution/network/persistence
sinks, privilege, destination control, authorization and stated purpose.
Documentation is evidence, not proof. Compare supplied manifests, lockfiles,
source and releases; differences may be generation, stale metadata, packaging
or tampering. Names, popularity and signatures do not establish safety.
Snippets establish local behavior, not release authenticity.

For example, a lifecycle hook calling a module that reads environment credentials
and forwards them to a network client warrants tracing which credentials, hook
activation, destination control and authorization. Harm may be High even when
the purpose remains unresolved. Do not run the hook to confirm this.

## Obfuscation

Reconstruct encoding, concatenation, indirect calls, lookups and hidden Unicode
as data only. Retain original digest/locator, ordered transforms, resulting
digests and consumer. Distinguish generation/minification, localization, embedded
assets, serialization and fixtures from concealment. Selective activation,
anti-analysis gates and review/runtime discrepancies require explanation and
alternatives. An unused encoded URL is not an exfiltration path; a sensitive
source connected to its reachable consumer is materially different.
Never evaluate or execute reconstructed data.

## Command and control

Trace `remote source -> channel/polling -> task parser -> dispatch -> response`.
Inspect accepted capabilities, authentication, privilege, persistence, fallback
channels and activation. URLs, beacons, encryption and retries alone are not C2.
Contrast authorized remote administration, distributed jobs, diagnostics and
updaters. Use "C2-like remote task dispatch" if compromise/intent is unverified.
Do not contact endpoints; use supplied evidence or propose isolated simulation.
MITRE's tactic concerns communicating with controlled compromised systems:
https://attack.mitre.org/tactics/TA0011/

## LLM-facing material

Trace `untrusted content -> claimed authority -> requested deviation -> sink`.
Review surrounding turns/quotes, role impersonation, review suppression,
tool-result laundering, privileged requests, disclosure and memory persistence.
Consider encoded, split, multilingual, hidden-Unicode and cross-document content.
Distinguish quoted attack examples from active instructions and attempts from
observed success. Unsupported multimodal content is a coverage limitation;
do not fetch remote assets to complete an attack.

| Claim | Required evidence |
|---|---|
| Prompt/context injection attempt | Untrusted instructions seeking deviation across an identified authority boundary. |
| Retrieval-corpus poisoning | Modified corpus, applicable retrieval/ingestion path and intended influence. |
| Memory poisoning | A path persisting untrusted instructions/claims as future authority. |
| Training-data poisoning | Relevant dataset modification and training ingestion, not suspicious prose alone. |
| Successful influence | Observed behavioral change or separately authorized controlled experiment. |

OWASP taxonomy: https://genai.owasp.org/llmrisk/llm01-prompt-injection/

Stop at exhausted evidence, limits, missing capabilities or scope boundaries.
Declare unsupported binaries/languages and missing runtime proof; do not replace
technical analysis with strings or imply full coverage from sampled paths.
