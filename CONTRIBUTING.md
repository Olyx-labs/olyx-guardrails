# Contributing

Thank you for improving Olyx Guardrails.

## Development setup

```bash
rbenv install
bundle install
bundle exec rake test
COVERAGE=true bundle exec rake test
bundle exec rubocop --cache false
bundle exec ruby script/flog_gate.rb
bundle exec rubycritic -f console -f json -p tmp/rubycritic
ruby script/rubycritic_gate.rb tmp/rubycritic/report.json
bundle exec appraisal install
bundle exec appraisal rake test
```

Ruby 3.4 or newer is supported. Changes must remain compatible with the oldest
supported Ruby unless the same pull request deliberately changes the gem's
requirement.

RubyCritic is a blocking regression gate configured in `.rubycritic.yml`.
Do not lower its baseline to merge a change. Refactor new hot spots and ratchet
the minimum upward when sustained improvements raise the measured score.
The minimum score is 95; new files must remain focused on one reason to change,
and every production file must remain A-rated. RubyCritic smells, duplication,
and per-file complexity are review signals, not automatic design instructions:
address genuine responsibility or clarity problems, but do not introduce proxy
methods, unnecessary indirection, or metaprogramming merely to silence a
heuristic.

Flog is also a blocking structural gate: ordinary methods must score at most
10, and each class or module must total at most 60. Do not split cohesive code,
hide behavior behind dynamic dispatch, or weaken a public API merely to improve
a score. A public DSL or metaprogramming macro may be listed in
`.flog_exemptions.yml` only when it is the clearest design; the entry must use
Flog's fully-qualified method name and contain an explicit DSL/metaprogramming
reason. Stale or unexplained exemptions fail CI.

The Appraisal matrix covers Rails 7.2, 8.0, and 8.1. Rails integration changes
must pass every configured Rails line while the standalone core remains free of
Rails runtime dependencies.

## Pull requests

1. Open an issue first for substantial API or policy changes.
2. Keep each pull request focused and include tests for behavior changes.
3. Add adversarial regression tests for security-sensitive fixes.
4. Update README, API reference, examples, and changelog when public behavior
   changes.
5. Confirm tests, RuboCop, Flog, RubyCritic, syntax checks, and gem packaging
   pass locally.

Never include real credentials, personal data, production endpoints, or
customer content in fixtures. Use clearly synthetic values.

By submitting a contribution, you agree that it is licensed under the
Apache-2.0 license used by this project.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public
issue tracker.
