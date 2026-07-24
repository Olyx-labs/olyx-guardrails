# frozen_string_literal: true

require_relative 'guardrails/version'
require_relative 'guardrails/errors'
require_relative 'guardrails/validation'
require_relative 'guardrails/risk/weights'
require_relative 'guardrails/pii_scrubber'
require_relative 'guardrails/injection_detector'
require_relative 'guardrails/secret_scanner'
require_relative 'guardrails/policy'
require_relative 'guardrails/check_runner'
require_relative 'guardrails/message_check_runner'
require_relative 'guardrails/redactor'
require_relative 'guardrails/notifier'
require_relative 'guardrails/rails' if defined?(Rails::Railtie)

module Olyx
  # Olyx libraries for Ruby applications.
  #
  # Olyx::Guardrails is the public namespace provided by this gem.

  # Guardrails is a standalone, in-process AI safety toolkit: custom policy
  # enforcement, PII redaction, prompt-injection detection, and secret scanning,
  # unified behind explicit decision and transformation entry points.
  #
  # Decisions and transformations are separate operations:
  #
  #   decision = Olyx::Guardrails.check(input, policy: policy)
  #   safe_text = Olyx::Guardrails.redact(input, policy: policy)[:text]
  #
  # Deterministic checks run locally. Content reaches an external service only
  # when the application supplies an +llm_provider+ that sends it there.
  #
  # The supported public surface is defined in docs/API.md. Other constants
  # under this namespace are implementation details and may change without
  # compatibility guarantees.
  module Guardrails
    INJECTION_RISK_WEIGHT = Risk::Weights::FINDINGS.fetch(:injection).last # :nodoc:
    SECRET_RISK_WEIGHT    = Risk::Weights::FINDINGS.fetch(:secret).last # :nodoc:
    PII_RISK_WEIGHT       = Risk::Weights::FINDINGS.fetch(:pii).last # :nodoc:
    POLICY_RISK_WEIGHT    = Risk::Weights::FINDINGS.fetch(:policy).last # :nodoc:
    BLOCKED_RISK_WEIGHT   = Risk::Weights::BLOCKED # :nodoc:

    # :call-seq:
    #   check(input, policy: Policy.default, llm_provider: nil) -> Hash
    #
    # Evaluates one completed input and returns an allow/block decision.
    #
    # +input+ is converted with +to_s+. +policy+ supplies length limits,
    # blocking behavior, secret patterns, and restricted-content rules.
    # +llm_provider+, when present, receives the converted text and a bounded
    # context Hash. Provider findings can add violations but cannot remove
    # deterministic findings.
    #
    # An oversized input returns a rejected decision without running content
    # scanners or the provider. Invalid arguments raise ArgumentError. A
    # provider failure raises LlmProviderError only when the policy uses
    # <tt>llm_failure_mode: :raise</tt>.
    #
    # See docs/API.md#decision-result for the returned Hash contract.
    def self.check(input, policy: Policy.default, llm_provider: nil)
      CheckRunner.call(input, policy: policy, llm_provider: llm_provider)
    end

    # :call-seq:
    #   check_messages(messages, policy: Policy.default, llm_provider: nil) -> Hash
    #
    # Evaluates structured chat +messages+ and returns an allow/block decision.
    #
    # +messages+ must be an Array of Hashes with String or Symbol keys.
    # Supported content is either a String or an Array of text blocks. In
    # addition to ordinary checks, adjacent user-to-assistant turns are scanned
    # for split prompt-injection patterns.
    #
    # +policy+ and +llm_provider+ behave as they do for check. Invalid message
    # structure raises ArgumentError.
    def self.check_messages(messages, policy: Policy.default, llm_provider: nil)
      MessageCheckRunner.call(messages, policy: policy, llm_provider: llm_provider)
    end

    # :call-seq:
    #   redact(input, policy: Policy.default) -> Hash
    #
    # Redacts recognized PII, secrets, and restricted-policy matches.
    #
    # +input+ is converted with +to_s+. +policy+ provides the input limit,
    # custom secret patterns, and restricted-content replacements. This method
    # transforms content and does not make an allow/block decision.
    #
    # Raises ArgumentError when +policy+ is invalid or the converted input
    # exceeds the policy limit. See docs/API.md#redaction-result for the
    # returned Hash contract.
    def self.redact(input, policy: Policy.default)
      Redactor.call(input, policy: policy)
    end

    class << self
      # :call-seq:
      #   check_output(output, policy: Policy.default, llm_provider: nil) -> Hash
      #
      # Evaluates completed model +output+. This is an explicit output-boundary
      # name for check; it does not inspect a token stream.
      alias check_output check

      # :call-seq:
      #   redact_output(output, policy: Policy.default) -> Hash
      #
      # Redacts completed model +output+. This is an explicit output-boundary
      # name for redact.
      alias redact_output redact
    end
  end
end
