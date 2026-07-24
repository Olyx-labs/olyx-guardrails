# Policies and Restricted Content

This guide explains how to build reusable policies for deterministic guardrail
decisions and redaction.

After reading this guide, the reader will know:

- how policy defaults affect allow/block decisions;
- when to use `secret_patterns`, `terms`, or `patterns`;
- how blocking and monitoring-only rules differ;
- how policy findings and replacements are represented; and
- how Rails loads policies from safe YAML.

## Policy overview

An `Olyx::Guardrails::Policy` is immutable. Validation and regular-expression
compilation happen during construction, so invalid configuration fails before
an input reaches a model.

```ruby
require "olyx/guardrails"

policy = Olyx::Guardrails::Policy.new(
  name: "production",
  max_input_length: 4_000,
  block_pii: true,
  block_injections: true,
  block_secrets: true,
  llm_failure_mode: :block,
  secret_patterns: ["company-token-[a-z0-9]{24}"],
  rules: [
    {
      name: :confidential_projects,
      description: "Internal project identifiers",
      terms: ["Project Falcon"],
      patterns: [/\bPF-\d{4}\b/],
      match: :whole_word,
      block: true,
      replacement: "[CONFIDENTIAL_PROJECT]"
    }
  ]
)
```

## Policy options

| Option | Default | Contract |
|---|---:|---|
| `name` | `"default"` | Non-blank String, at most 100 characters |
| `max_input_length` | `10_000` | Non-negative Integer measured in Ruby characters |
| `block_pii` | `false` | Blocks when a PII finding exists |
| `block_injections` | `true` | Blocks when an injection finding exists |
| `block_secrets` | `false` | Blocks when a secret finding exists |
| `llm_failure_mode` | `:allow` | One of `:allow`, `:block`, or `:raise` |
| `secret_patterns` | `[]` | Array of regular-expression source Strings |
| `rules` | `[]` | Array of `PolicyRule` objects or String/Symbol-keyed Hashes |

All Boolean options require literal `true` or `false`. Policy objects and their
compiled rule collections are frozen.

## Default policy

`Policy.default` returns one reused immutable policy. Its behavior is:

| Finding | Reported | Blocked |
|---|---:|---:|
| Input longer than 10,000 characters | Yes | Yes |
| Prompt injection | Yes | Yes |
| PII | Yes | No |
| Secret | Yes | No |
| Restricted content | Not configured | No |
| Supplied LLM provider fails | Yes, under `llm_analysis` | No |

An explicit policy is recommended for production. In particular, applications
that require semantic analysis should set `llm_failure_mode` to `:block` or
`:raise`.

## Secret patterns and policy rules

`secret_patterns` extends credential-format detection. Matches remain in the
`secret` category and use the standard secret replacement.

```ruby
policy = Olyx::Guardrails::Policy.new(
  secret_patterns: [
    "company-token-[a-z0-9]{24}",
    "internal-key-[A-F0-9]{32}"
  ]
)
```

Use a policy rule when a finding needs an organization-specific identifier,
description, blocking decision, or replacement.

```ruby
rule = Olyx::Guardrails::PolicyRule.new(
  name: :export_controlled_terms,
  terms: ["Program Orion"],
  match: :whole_word,
  block: true,
  description: "Export-controlled program names",
  replacement: "[EXPORT_CONTROLLED]"
)
```

## Policy rule options

| Option | Default | Contract |
|---|---:|---|
| `name` | required | String or Symbol matching `[A-Za-z][A-Za-z0-9_.:-]*` |
| `terms` | `[]` | Array of non-empty Strings |
| `patterns` | `[]` | Array of Strings or Regexps |
| `match` | `:substring` | `:substring`, `:whole_word`, or `:regexp`; applies to `terms` |
| `block` | `true` | Literal Boolean |
| `description` | `nil` | Non-blank String up to 500 characters, or `nil` |
| `replacement` | generated | Single-line String from 1 through 100 characters |

Every rule defines at least one term or pattern. Rule names are unique within a
policy.

When `replacement` is omitted, the default is derived from the rule name:

```ruby
Olyx::Guardrails::PolicyRule.new(
  name: :confidential_project,
  terms: ["Project Falcon"]
).replacement
# => "[RESTRICTED:CONFIDENTIAL_PROJECT]"
```

## Match modes

### Substring

`:substring` is the default. Terms are escaped and matched
case-insensitively anywhere in the input.

```ruby
{ name: :project, terms: ["Falcon"], match: :substring }
```

This rule matches both `Falcon` and `Falconry`.

### Whole word

`:whole_word` adds alphanumeric and underscore boundaries around the escaped
term.

```ruby
{ name: :project, terms: ["Falcon"], match: :whole_word }
```

This rule matches `Project Falcon` but not `Falconry`.

### Regular expression

`:regexp` interprets values under `terms` as regular-expression source.

```ruby
{ name: :project_code, terms: ["PF-\\d{4}"], match: :regexp }
```

Use `patterns` when regular-expression semantics should be explicit:

```ruby
{
  name: :project_code,
  patterns: ["\\bPF-[0-9]{4}\\b", /ORION-\d+/i]
}
```

String patterns compile case-insensitively. Regexps retain their flags. All
compiled expressions use a 100-millisecond match timeout and must not match an
empty string.

Configured regular expressions are trusted application configuration. Review
them for excessive backtracking before deployment.

## Blocking and monitoring

A blocking rule causes `Guardrails.check` to return `allowed: false`.
A monitoring-only rule records the finding without rejecting the input.

```ruby
rules = [
  {
    name: :confidential_projects,
    terms: ["Project Falcon"],
    block: true
  },
  {
    name: :competitor_references,
    terms: ["Competitor Corp"],
    block: false
  }
]
```

Both rules participate in `Guardrails.redact`. The `block` option controls the
decision, not whether a transformation is available.

## Finding contract

Policy findings never contain the matched restricted text:

```ruby
{
  rule: "confidential_projects",
  description: "Internal project identifiers",
  blocked: true,
  matched: "[REDACTED]",
  fingerprint: "sha256:...",
  start: 8,
  end: 22
}
```

`description` is omitted when the rule has no description. `start` is
inclusive, and `end` is exclusive. Fingerprints support correlation without
revealing plaintext.

## Loading Hash configuration

`Policy.from_h` accepts top-level String or Symbol keys:

```ruby
policy = Olyx::Guardrails::Policy.from_h(
  "name" => "production",
  "block_secrets" => true,
  "rules" => [
    {
      "name" => "confidential_projects",
      "terms" => ["Project Falcon"]
    }
  ]
)
```

Rule hashes may also use String or Symbol keys. Unknown keys and invalid values
raise `ArgumentError`; configuration does not silently fall back to defaults.

## Rails YAML

The Rails generator creates `config/olyx_guardrails.yml` with one policy per
environment:

```yaml
production:
  name: production
  max_input_length: 4000
  block_pii: true
  block_injections: true
  block_secrets: true
  llm_failure_mode: block
  secret_patterns:
    - 'company-token-[a-z0-9]{24}'
  rules:
    - name: confidential_projects
      description: Internal project names
      terms:
        - 'Project Falcon'
      match: whole_word
      block: true
      replacement: '[CONFIDENTIAL_PROJECT]'
```

The loader uses `YAML.safe_load_file` with aliases and custom classes disabled.
ERB is not evaluated. Missing, unreadable, malformed, unsafe, or invalid policy
files raise `Olyx::Guardrails::ConfigurationError` during Rails boot.

A file may instead contain one direct policy hash. Do not mix direct policy
keys with environment sections.

## Reusing a policy

Construct a policy once and reuse it for decisions, redaction, and
notifications:

```ruby
decision = Olyx::Guardrails.check(input, policy: policy)
redaction = Olyx::Guardrails.redact(input, policy: policy)

notifier = Olyx::Guardrails::Notifier.new(
  policy: policy,
  handlers: { audit: ->(event) { AuditLog.write(event) } }
)
```

Passing the same policy to the notifier ensures that previews, metadata, and
handler errors use the same restricted-content replacements.

See the [API reference](API.md#olyxguardrailspolicy) for the exact constructor,
readers, and exception contracts.
