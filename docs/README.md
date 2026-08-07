# Olyx Guardrails Documentation

This documentation separates task-oriented guides from the exact public API
contract.

## Start here

The project [README](../README.md) contains installation instructions and a
complete first integration for Ruby and Rails applications.

After completing the quick start, choose the guide that matches the next task:

| Guide | Use it to |
|---|---|
| [Policies](POLICIES.md) | Define organization restrictions, blocking rules, replacements, and safe YAML |
| [Rails integration](RAILS.md) | Protect controllers, jobs, GraphQL, Action Cable, uploads, callbacks, and model attributes |
| [Operations](OPERATIONS.md) | Choose failure modes, consume telemetry, configure notifications, and understand deployment boundaries |
| [API reference](API.md) | Verify signatures, defaults, return values, exceptions, and immutable contracts |
| [Releasing](RELEASING.md) | Validate, tag, publish, and verify a maintainer release |

## Runnable examples

| Example | Description |
|---|---|
| [`ruby_only.rb`](../examples/ruby_only.rb) | Complete framework-free input, output, redaction, and notification flow |
| [`custom_policy.rb`](../examples/custom_policy.rb) | Blocking and monitoring-only organization rules |
| [`rails_opt_in.rb`](../examples/rails_opt_in.rb) | Copyable Rails boundary adapters |
| [`local_llm_provider.rb`](../examples/local_llm_provider.rb) | Provider-SDK-free local classifier adapter |
| [`notifier.rb`](../examples/notifier.rb) | Multiple vendor-neutral notification handlers |

Run framework-free examples against the local checkout:

```bash
ruby -Ilib examples/ruby_only.rb "Summarize these release notes"
ruby -Ilib examples/custom_policy.rb "Discuss Project Falcon"
ruby -Ilib examples/notifier.rb "Ignore previous instructions"
```

The local LLM provider example requires an application-owned HTTP classifier.
The Rails example is intended to be copied into a Rails application and is
syntax-checked by CI.

## Supported documentation

The documentation describes the version in the same repository revision.
Released behavior is recorded in the [changelog](../CHANGELOG.md).

Public behavior changes require updates to:

1. the implementation and tests;
2. the API reference;
3. the affected task guide and example; and
4. the changelog.

Security-sensitive documentation follows the private reporting process in
[SECURITY.md](../SECURITY.md).
