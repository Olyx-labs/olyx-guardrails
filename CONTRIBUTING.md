# Contributing

Thank you for improving Olyx Guardrails.

## Development setup

```bash
bundle install
bundle exec rake test
```

Ruby 3.1 or newer is supported. Changes must remain compatible with the oldest
supported Ruby unless the same pull request deliberately changes the gem's
requirement.

## Pull requests

1. Open an issue first for substantial API or policy changes.
2. Keep each pull request focused and include tests for behavior changes.
3. Add adversarial regression tests for security-sensitive fixes.
4. Update README, API reference, examples, and changelog when public behavior
   changes.
5. Confirm tests, syntax checks, and gem packaging pass locally.

Never include real credentials, personal data, production endpoints, or
customer content in fixtures. Use clearly synthetic values.

By submitting a contribution, you agree that it is licensed under the
Apache-2.0 license used by this project.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public
issue tracker.
