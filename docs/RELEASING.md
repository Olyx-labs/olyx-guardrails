# Releasing Olyx Guardrails

This runbook defines the maintainer workflow for publishing a release. Release
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

Build and inspect the release artifact:

```bash
gem build olyx-guardrails.gemspec
gem specification ./olyx-guardrails-*.gem
```

Confirm the artifact version, metadata, runtime dependencies, required Ruby
version, license, and file manifest. The built gem must not contain credentials,
customer data, coverage output, temporary reports, or development caches.

## Publish

1. Commit the release changes.
2. Create a signed tag matching the gem version, for example `v1.1.0`.
3. Push the commit and tag, then wait for every required GitHub check.
4. Publish the exact inspected artifact with RubyGems MFA or a narrowly scoped
   trusted publisher:

   ```bash
   gem push olyx-guardrails-1.1.0.gem
   ```

5. Create the GitHub release from the signed tag using the matching changelog
   section.

Never rebuild between inspection and publication.

## Verify

After publication:

1. confirm RubyGems shows the expected version, dependency, MFA, license, and
   source metadata;
2. confirm the GitHub release and tag resolve to the published source;
3. verify README badges and documentation links resolve from the canonical
   repository; and
4. announce the release only after these checks pass.

If verification fails, stop promotion and publish a corrective patch. Do not
replace or silently retag an existing release.
