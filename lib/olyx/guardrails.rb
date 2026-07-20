# frozen_string_literal: true

require_relative "guardrails/version"
require_relative "guardrails/validation"
require_relative "guardrails/pii_scrubber"
require_relative "guardrails/injection_detector"
require_relative "guardrails/secret_scanner"
require_relative "guardrails/check_runner"
require_relative "guardrails/redactor"

module Olyx
  # Guardrails is a standalone, in-process AI safety toolkit: PII redaction,
  # prompt-injection detection, and secret scanning, unified behind explicit
  # decision and transformation entry points.
  module Guardrails
    INJECTION_RISK_WEIGHT = 0.50
    SECRET_RISK_WEIGHT    = 0.25
    PII_RISK_WEIGHT       = 0.10
    BLOCKED_RISK_WEIGHT   = 0.15

    # Runs the full guardrail suite on one input, optionally enriched by a
    # caller-supplied AI analyzer. AI findings can add violations but cannot
    # clear deterministic findings.
    #
    # @param input [#to_s] the content to check.
    # @param max_input_length [Integer] maximum accepted input length.
    # @param block_injections [Boolean] whether injection findings block.
    # @param block_secrets [Boolean] whether secret findings block.
    # @param custom_patterns [Array<String>] additional secret regex strings.
    # @param ai_analyzer [#call, nil] optional semantic analyzer receiving
    #   `(text, context)`.
    # @return [Hash] the aggregate decision, findings, score, and check details.
    def self.check(
      input,
      max_input_length: 10_000,
      block_injections: true,
      block_secrets: false,
      custom_patterns: [],
      ai_analyzer: nil
    )
      CheckRunner.call(
        input,
        max_input_length: max_input_length,
        block_injections: block_injections,
        block_secrets: block_secrets,
        custom_patterns: custom_patterns,
        ai_analyzer: ai_analyzer
      )
    end

    # Redacts regex-detected PII and secrets without making an allow/block
    # decision.
    #
    # @param input [#to_s] the content to redact.
    # @param max_input_length [Integer] maximum accepted input length.
    # @param custom_patterns [Array<String>] additional secret regex strings.
    # @return [Hash] redacted text, detection flags, and safe secret findings.
    # @raise [ArgumentError] when an option is invalid or input is oversized.
    def self.redact(input, max_input_length: 10_000, custom_patterns: [])
      Redactor.call(
        input,
        max_input_length: max_input_length,
        custom_patterns: custom_patterns
      )
    end
  end
end
