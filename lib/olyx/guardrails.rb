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
  # Guardrails is a standalone, in-process AI safety toolkit: custom policy
  # enforcement, PII redaction, prompt-injection detection, and secret scanning,
  # unified behind explicit decision and transformation entry points.
  module Guardrails
    INJECTION_RISK_WEIGHT = Risk::Weights::FINDINGS.fetch(:injection).last
    SECRET_RISK_WEIGHT    = Risk::Weights::FINDINGS.fetch(:secret).last
    PII_RISK_WEIGHT       = Risk::Weights::FINDINGS.fetch(:pii).last
    POLICY_RISK_WEIGHT    = Risk::Weights::FINDINGS.fetch(:policy).last
    BLOCKED_RISK_WEIGHT   = Risk::Weights::BLOCKED

    # Runs the full guardrail suite on one input, optionally enriched by a
    # caller-supplied AI analyzer. AI findings can add violations but cannot
    # clear deterministic findings.
    #
    # @param input [#to_s] the content to check.
    # @param policy [Policy] reusable enforcement and restricted-content rules.
    # @param ai_analyzer [#call, nil] optional semantic analyzer receiving
    #   `(text, context)`.
    # @return [Hash] the aggregate decision, findings, score, and check details.
    def self.check(input, policy: Policy.default, ai_analyzer: nil)
      CheckRunner.call(input, policy: policy, ai_analyzer: ai_analyzer)
    end

    # Runs guardrails against structured chat messages, including adjacent-turn detection.
    def self.check_messages(messages, policy: Policy.default, ai_analyzer: nil)
      MessageCheckRunner.call(messages, policy: policy, ai_analyzer: ai_analyzer)
    end

    # Redacts regex-detected PII, secrets, and restricted policy matches without
    # making an allow/block decision.
    #
    # @param input [#to_s] the content to redact.
    # @param policy [Policy] reusable limits and restricted-content rules.
    # @return [Hash] redacted text, detection flags, and safe findings.
    # @raise [ArgumentError] when an option is invalid or input is oversized.
    def self.redact(input, policy: Policy.default)
      Redactor.call(input, policy: policy)
    end

    class << self
      # Explicit completed-output entry points; streaming enforcement belongs to the proxy platform.
      alias check_output check
      alias redact_output redact
    end
  end
end
