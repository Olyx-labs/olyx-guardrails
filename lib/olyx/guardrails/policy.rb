# frozen_string_literal: true

require_relative 'policy/configuration_hash'
require_relative 'policy/configuration'

module Olyx # :nodoc:
  module Guardrails
    # Defines immutable limits, blocking behavior, and restricted-content rules.
    #
    # Policy validates and compiles all configuration during construction. A
    # successfully constructed instance is frozen and safe to reuse across
    # requests and threads.
    #
    #   policy = Olyx::Guardrails::Policy.new(
    #     name: "production",
    #     block_secrets: true,
    #     rules: [
    #       { name: :project, terms: ["Project Falcon"] }
    #     ]
    #   )
    #
    # See docs/POLICIES.md for matching and replacement semantics.
    class Policy
      # :call-seq:
      #   Policy.default -> Policy
      #
      # Returns the shared default policy. The default blocks prompt injection,
      # reports PII and secrets without blocking them, and has no custom rules.
      def self.default
        @default ||= new
      end

      # :call-seq:
      #   Policy.from_h(configuration) -> Policy
      #
      # Constructs a policy from +config+, which must be a Hash with String or
      # Symbol keys. Unknown keys and invalid values raise ArgumentError.
      def self.from_h(config)
        new(**PolicyComponents::ConfigurationHash.call(config))
      end

      # :call-seq:
      #   Policy.new(name: "default", max_input_length: 10_000,
      #              block_pii: false, block_injections: true,
      #              block_secrets: false, llm_failure_mode: :allow,
      #              secret_patterns: [], rules: []) -> Policy
      #
      # Builds and freezes a policy.
      #
      # +name+ identifies decisions and notifications. +max_input_length+ is a
      # non-negative character limit. +block_pii+, +block_injections+, and
      # +block_secrets+ require literal Boolean values.
      #
      # +llm_failure_mode+ is +:allow+, +:block+, or +:raise+.
      # +secret_patterns+ extends secret detection with regular-expression
      # source Strings. +rules+ contains PolicyRule instances or rule Hashes.
      #
      # Invalid values, duplicate rule names, invalid expressions, and
      # expressions that match empty text raise ArgumentError.
      def initialize(
        name: 'default',
        max_input_length: 10_000,
        block_pii: false,
        block_injections: true,
        block_secrets: false,
        llm_failure_mode: :allow,
        secret_patterns: [],
        rules: []
      )
        @configuration = PolicyComponents::Configuration.new(
          identity: [name, max_input_length],
          blocking: [block_pii, block_injections, block_secrets],
          restrictions: [llm_failure_mode, secret_patterns, rules]
        )
        freeze
      end

      # Returns the policy's stable String identifier.
      def name = @configuration.identity.name

      # Returns the maximum accepted input length in Ruby characters.
      def max_input_length = @configuration.identity.max_input_length

      # Returns +:allow+, +:block+, or +:raise+.
      def llm_failure_mode = @configuration.restrictions.llm_failure_mode

      # Returns the frozen custom secret regular-expression source Strings.
      def secret_patterns = @configuration.restrictions.secret_patterns

      # Returns the frozen PolicyRule collection.
      def rules = @configuration.restrictions.rules

      # Returns whether PII findings block a decision.
      def block_pii? = @configuration.blocking.pii?

      # Returns whether prompt-injection findings block a decision.
      def block_injections? = @configuration.blocking.injections?

      # Returns whether secret findings block a decision.
      def block_secrets? = @configuration.blocking.secrets?
    end
  end
end
