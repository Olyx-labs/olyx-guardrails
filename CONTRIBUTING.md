# Contributing

Thank you for improving Olyx Guardrails.

## Development setup

```bash
rbenv install
bundle install
bundle exec rake test
COVERAGE=true bundle exec rake test
bundle exec rubycritic
```

Ruby 3.4 or newer is supported. Changes must remain compatible with the oldest
supported Ruby unless the same pull request deliberately changes the gem's
requirement.

RubyCritic is a blocking regression gate configured in `.rubycritic.yml`.
Do not lower its baseline to merge a change. Refactor new hot spots and ratchet
the minimum upward when sustained improvements raise the measured score.

## Pull requests

1. Open an issue first for substantial API or policy changes.
2. Keep each pull request focused and include tests for behavior changes.
3. Add adversarial regression tests for security-sensitive fixes.
4. Update README, API reference, examples, and changelog when public behavior
   changes.
5. Confirm tests, RubyCritic, syntax checks, and gem packaging pass locally.

Never include real credentials, personal data, production endpoints, or
customer content in fixtures. Use clearly synthetic values.

By submitting a contribution, you agree that it is licensed under the
Apache-2.0 license used by this project.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public
issue tracker.
