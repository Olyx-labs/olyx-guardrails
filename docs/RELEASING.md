# Releasing Olyx Guardrails

This runbook defines the maintainer workflow for publishing a release. Releases
publish through RubyGems trusted publishing from a signed Git tag. Release
credentials never belong in the repository, local configuration examples, or
CI logs.

## Prepare

1. Start from a clean, protected default branch.
2. Confirm the gemspec source, documentation, changelog, and issue URLs point
   to the canonical public repository.
3. Choose the next semantic version and update
   `lib/olyx/guardrails/version.rb`.
4. Move the relevant entries from `Unreleased` into a dated changelog section.
5. Confirm public behavior, examples, API documentation, and migration notes
   describe the release exactly.

## Validate

Run the complete local gate and Rails compatibility matrix:

```bash
bin/setup
bin/ci
bundle exec appraisal rake test
bundle exec bundle-audit check --update
```

Build and inspect the release artifact without publishing it:

```bash
bundle exec rake build
gem specification ./pkg/olyx-guardrails-*.gem
```

Confirm the artifact version, metadata, runtime dependencies, required Ruby
version, license, and file manifest. The built gem must not contain credentials,
customer data, coverage output, temporary reports, or development caches.

## Publish

1. Merge the release pull request into the protected default branch.
2. Confirm RubyGems has a trusted publisher for `olyx-guardrails` with:

   | Field | Value |
   |---|---|
   | Repository owner | `Olyx-labs` |
   | Repository name | `olyx-guardrails` |
   | Workflow filename | `release.yml` |
   | Environment | `release` |

3. Create a signed tag matching the gem version on the current default branch:

   ```bash
   git switch master
   git pull --ff-only origin master
   version=$(ruby -Ilib -rolyx/guardrails/version -e 'print Olyx::Guardrails::VERSION')
   git tag -s "v${version}" -m "Release v${version}"
   git push origin "v${version}"
   ```

4. Wait for the `Release gem` workflow to pass. The workflow runs the CI gate,
   builds the gem from the tagged source, and publishes through RubyGems trusted
   publishing.
5. Create the GitHub release from the signed tag using the matching changelog
   section:

   ```bash
   version=$(ruby -Ilib -rolyx/guardrails/version -e 'print Olyx::Guardrails::VERSION')
   gh release create "v${version}" --verify-tag --title "v${version}" --notes-file release-notes.md
   ```

Do not run `gem push` or `bundle exec rake release` locally for the normal
path. If automation is unavailable, use a manual RubyGems MFA publish only
after confirming the version has not been published and the inspected artifact
matches the intended source.

## Verify

After publication:

1. confirm RubyGems shows the expected version, dependency, MFA, license, and
   source metadata;
2. confirm the GitHub release and signed tag resolve to the published source;
3. verify README badges show the current RubyGems version and GitHub release;
4. verify documentation links resolve from the canonical repository; and
5. announce the release only after these checks pass.

If verification fails, stop promotion and publish a corrective patch. Do not
replace or silently retag an existing release.
