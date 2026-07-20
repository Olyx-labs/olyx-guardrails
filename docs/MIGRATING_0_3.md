# Migrating to 0.3

Version 0.3 deliberately separates policy decisions from text transformation.

## Top-level checks

Before:

```ruby
Olyx::Guardrails.check(
  input,
  injection_block: true,
  secret_action: "block"
)
```

After:

```ruby
Olyx::Guardrails.check(
  input,
  block_injections: true,
  block_secrets: true
)
```

`secret_action: "redact"` has no direct replacement on `check`, because a
decision method no longer transforms text. Use:

```ruby
redaction = Olyx::Guardrails.redact(input)
safe_input = redaction[:text]
```

## Secret scanner

Before:

```ruby
SecretScanner.baseline_scan(text)
SecretScanner.scan(text, secret_action: "alert")
SecretScanner.scan(text, secret_action: "redact")
SecretScanner.scan(text, secret_action: "block")
```

After:

```ruby
SecretScanner.scan(text)
SecretScanner.redact(text)
SecretScanner.scan!(text)
```

Findings no longer contain plaintext excerpts. Use `:fingerprint` to correlate
the same synthetic or production finding without storing the credential.

## Invalid configuration

Invalid Boolean options, malformed message arrays, invalid custom-pattern
types, and invalid regex strings now raise `ArgumentError`. Applications should
validate configuration at boot and treat these errors as deployment failures.
