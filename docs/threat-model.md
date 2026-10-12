# PromptSieve threat model

## Protected boundary

PromptSieve inspects supported request text crossing from an integrating application to a fixed OpenAI origin. It can prevent a flagged request from being transmitted at all in enforce mode. It authenticates clients with a proxy bearer token distinct from the server's upstream API key. Possession of that token grants use of the configured upstream account; this MVP has no tenant isolation, per-user quotas, or authorization policy for individual models/tools.

The operator controls configuration, origin, deployment, and credentials. The integrating application must control trusted system/developer instructions, conversation assembly, and tool execution. A client-supplied role label is not proof of trust. PromptSieve retains declared roles as context and scans privileged-role text, but cannot authenticate the provenance of individual messages. Do not expose an unrestricted role-editing API to untrusted users and expect pattern matching to make it safe.

## Threats addressed

Baseline detectors flag some attempts to override instructions, impersonate roles, disclose system instructions, or hide such requests using Unicode formatting or base64/hex. The complete bounded request is inspected before any generation request is sent. Enforce blocks high/medium findings without rewriting content; monitor observes and forwards unchanged.

The transport does not accept a client-selected destination, follow upstream redirects, forward client authentication, or retry generation. The origin must be trusted: an operator-configured origin receives the upstream key. TLS verification remains enabled. Content URLs are never fetched by the proxy. Request limits and admission control bound concurrent body buffering; deadlines and cancellation bound network lifetimes.

## Known bypasses and false positives

These are fallible, predominantly English, lexical heuristics. Semantic paraphrases, multilingual attacks, misspellings, homoglyphs, multi-turn attacks, long-distance dependencies, encoded payloads, and indirect instructions can evade detection. Boundaries between separate messages remain intact, so split attacks across messages may evade matching. Quoted malicious instructions and negated instructions may be downgraded; attackers can imitate benign quotation or research framing. Benign imperative text can be blocked. Severity expresses rule policy, not a measured probability.

Unicode NFKC normalization and removal of format characters happen only in the inspection view. Base64 and hex checks examine at most 16 candidate tokens per encoding per segment, between 24 and 2048 characters, with one decoding layer; they do not recursively decode, decompress, execute, or interpret arbitrary encodings. Pattern context windows are bounded. None of these transformations sanitizes forwarded input.

PromptSieve does not enforce the downstream model's instruction hierarchy, verify factual accuracy, classify all harmful content, prevent every secret disclosure, or make tool execution safe. Apply least-privilege tools, output handling, application authorization, sandboxing, and human review where appropriate. Generated responses are relayed unchanged and are not inspected; upstream error bodies are also relayed and must be treated as potentially sensitive by clients.

## Uninspected content

Only traffic routed through this proxy is inspected. Direct calls to OpenAI or another provider bypass it. Server-side retrieval, hosted tools, stored prompts, hidden conversation history, and tool execution may introduce content the proxy cannot see. Enforce mode rejects known request features that refer to such unavailable content, including hosted tools and previous-response/conversation references. Unknown features are rejected instead of silently assumed safe.

Enforce also rejects unsupported images, audio, files, encrypted reasoning, non-text input parts, and unknown fields. Monitor mode forwards inspection gaps and records them; its presence does not make unsupported content inspected. Plaintext results from application-managed tools can be inspected when explicitly included in a subsequent supported request. The application remains responsible for routing every relevant step through PromptSieve.

Opaque semantics can exist even in strings: the proxy cannot know what a URL, identifier, code snippet, or tool argument will cause another system to retrieve or execute. Inspectable text does not imply safe downstream behavior. Unsupported routes are not proxied.

## Privacy and operations

No prompt/response persistence is implemented. Audit logs contain generated request IDs, fixed reason strings, known field paths, detector IDs, decisions, and timing; these still reveal traffic patterns and should have appropriate access controls and retention. Credentials are not logged. Configure ingress/server logging to avoid raw queries, headers, bodies, and wire traces; the supplied launch commands disable Uvicorn access logs.

Health checks reveal only process readiness and make no upstream calls. Concurrency limits are per worker, not distributed or per tenant. Request bodies are limited to 1 MiB by default; nesting is capped at 32. TLS termination, network exposure, ingress header limits, slow-connection protection, token rotation, spending controls, and stronger identity management are operator responsibilities.

Generation may continue or incur charges after a disconnect or timeout. No automatic generation retries are performed. Once streaming headers are sent, a subsequent error cannot become a JSON HTTP error; the stream is interrupted and the audit event records why. Clients must handle incomplete streams.

## Evaluation limits and future work

The included malicious/benign fixtures are a small synthetic regression suite, developed with these rules, not a held-out effectiveness study. Detection rate and false-positive rate are reported separately; neither estimates real-world performance. Evaluate on application-specific data, including benign lookalikes and adversarial examples, before relying on enforce mode operationally.

The Detector protocol allows a future dedicated classifier without changing policy or transport. Such a classifier must continue to treat supplied text as untrusted data. Sanitization is reserved for a later, explicitly designed phase; the MVP never deletes phrases and forwards the remainder.
