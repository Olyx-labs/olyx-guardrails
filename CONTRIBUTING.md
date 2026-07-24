# Contributing

Thank you for improving Olyx Guardrails.

## Development setup

Detection logic (`lib/olyx/guardrails/pii/`, `secrets/`, `injection_detector.rb`,
`policy*`, and friends) remains independent of Rails at gem runtime. The
repository installs Rails as a development and test dependency so every
contributor runs the integration tests from the same default bundle. Consuming
applications that use only `require "olyx/guardrails"` do not load Rails.

Prepare the complete development bundle:

```bash
rbenv install
bin/setup
```

Run the complete pre-pull-request gate:

```bash
bin/ci
```

`bin/ci` runs coverage-enforced tests, documentation validation, public RDoc
coverage, RuboCop, RubyCritic, and the strict per-file quality gate. Individual
tests remain runnable through `bundle exec ruby -Itest path/to/test_file.rb`.
CI separately refreshes the Ruby advisory database and audits the committed
dependency lockfile. This network-backed check stays outside `bin/ci` so the
local quality gate remains reproducible offline after setup.

### Rails adapter changes

```bash
bundle exec appraisal rake test
```

Run this in addition to the above only when the change touches
`lib/olyx/guardrails/rails/`, `lib/generators/`, or their tests. The Appraisal
matrix covers Rails 8.0 and 8.1; Rails integration changes must pass every
configured line while the standalone core remains free of Rails runtime
dependencies.

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

RuboCop's `Metrics/AbcSize` (max 10), `Metrics/CyclomaticComplexity` (max 7),
`Metrics/PerceivedComplexity` (max 7), and `Metrics/ClassLength` (max 60 lines)
are the blocking structural-complexity gate, calibrated against this
codebase's measured distribution rather than RuboCop's looser defaults. Do not
split cohesive code, hide behavior behind dynamic dispatch, or weaken a public
API merely to improve a score. A public DSL or metaprogramming macro that
genuinely needs more room is a `# rubocop:disable` with an inline reason, or a
file-level exclude in `.rubocop.yml` with a comment explaining the constraint
— reviewed like any other exception, not a separate exemption file.

## Documentation

Public documentation follows the same contract discipline as production code:

- write simple, declarative sentences in the present tense;
- keep the README focused on the shortest correct integration;
- place task-oriented explanations in the appropriate guide;
- keep signatures, defaults, return shapes, and exceptions in `docs/API.md`;
- use complete, copyable examples with synthetic data;
- link to one canonical explanation instead of duplicating it; and
- update documentation and tests in the same change as public behavior.

Run `ruby script/documentation_gate.rb` after changing Markdown. The gate checks
local files and heading anchors. CI also syntax-checks every Ruby example.

Public code comments use native RDoc conventions and the same concise,
declarative style. Document behavior, accepted arguments, return values,
exceptions, security boundaries, and non-obvious edge cases. Do not narrate
implementation mechanics or repeat the method name. Add supported source files
to the RDoc whitelist in `olyx-guardrails.gemspec`; implementation-only
constants remain outside that manifest and are not compatibility commitments.

## Pull requests

1. Open an issue first for substantial API or policy changes.
2. Keep each pull request focused and include tests for behavior changes.
3. Add adversarial regression tests for security-sensitive fixes.
4. Update README, API reference, examples, and changelog when public behavior
   changes.
5. Confirm tests, RuboCop, RubyCritic, syntax checks, and gem packaging pass
   locally — plus the Appraisal Rails matrix if the change touches
   `lib/olyx/guardrails/rails/` or `lib/generators/`.

Maintainer releases follow [docs/RELEASING.md](docs/RELEASING.md). Do not
publish an artifact that has not completed that runbook.

Never include real credentials, personal data, production endpoints, or
customer content in fixtures. Use clearly synthetic values.

By submitting a contribution, you agree that it is licensed under the
Apache-2.0 license used by this project.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public
issue tracker.
