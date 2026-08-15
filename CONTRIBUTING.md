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

Run the standard local checks:

```bash
bin/ci
```

`bin/ci` runs coverage-enforced tests, documentation validation, public RDoc
coverage, and RuboCop. Individual tests remain runnable through
`bundle exec ruby -Itest path/to/test_file.rb`. CI separately refreshes the
Ruby advisory database and audits the committed dependency lockfile. This
network-backed check stays outside `bin/ci` so local validation remains
reproducible offline after setup.

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

RuboCop keeps style and complexity checks consistent across contributions.
Prefer small, direct objects with clear names. Do not split cohesive code, hide
behavior behind dynamic dispatch, or weaken a public API merely to satisfy a
metric. When a public DSL or metaprogramming macro genuinely needs more room,
use `# rubocop:disable` with an inline reason, or a file-level exclude in
`.rubocop.yml` with a comment explaining the constraint.

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

Contributions follow the same fork-and-pull-request workflow used by established
open-source projects:

1. Open an issue first for substantial API, policy, or architectural changes.
   Small fixes may go directly to a pull request.
2. Fork the repository and create a focused branch from the latest `master`.
   Do not work directly on `master`.
3. Add tests for behavior changes and adversarial regression tests for
   security-sensitive fixes.
4. Update README, API reference, examples, and changelog when public behavior
   changes.
5. Run `bin/ci` locally, plus the Appraisal Rails matrix when the change touches
   `lib/olyx/guardrails/rails/` or `lib/generators/`.
6. Open a draft pull request early when maintainer feedback would prevent
   rework. Mark it ready only when its description and validation checklist are
   complete.

Pull requests run with read-only GitHub token permissions, including
contributions from forks. CI never requires repository secrets. The protected
default branch requires the supported Ruby and Rails matrix, dependency audit,
CodeQL analysis, resolved review conversations, and valid commit signatures.
The project currently has one maintainer, so independent approval is encouraged
but not a branch-rule requirement; every merge still goes through a pull
request after the required checks pass. Maintainers squash merged pull
requests, and GitHub deletes the source branch after merge.

Maintainers may ask for a pull request to be split when unrelated behavior,
refactoring, or generated dependency changes make review unsafe. Force-pushing
a contributor branch is acceptable while responding to review; GitHub
dismisses stale approvals when the protected branch changes.

Maintainer releases follow [docs/RELEASING.md](docs/RELEASING.md). Do not
publish an artifact that has not completed that runbook.

Never include real credentials, personal data, production endpoints, or
customer content in fixtures. Use clearly synthetic values.

By submitting a contribution, you agree that it is licensed under the
Apache-2.0 license used by this project.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public
issue tracker.
