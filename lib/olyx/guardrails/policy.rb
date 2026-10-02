# frozen_string_literal: true

require_relative 'policy/configuration_hash'
require_relative 'policy/name'
require_relative 'policy/rule_collection'
require_relative 'policy/secret_pattern_collection'
require_relative 'enum_value'
require_relative 'validation'

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
      LLM_FAILURE_MODE = EnumValue.new(
        allowed: %i[allow block raise],
        error: 'policy llm_failure_mode must be allow, block, or raise'
      )
      private_constant :LLM_FAILURE_MODE

      # Returns the policy's stable String identifier.
      attr_reader :name

      # Returns the maximum accepted input length in Ruby characters.
      attr_reader :max_input_length

      # Returns +:allow+, +:block+, or +:raise+.
      attr_reader :llm_failure_mode

      # Returns the frozen custom secret regular-expression source Strings.
      attr_reader :secret_patterns

      # Returns the frozen PolicyRule collection.
      attr_reader :rules

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
        @name = PolicyComponents::Name.call(name)
        @max_input_length = Validation.non_negative_integer!(max_input_length, name: 'policy max_input_length')
        @block_pii = Validation.boolean!(block_pii, name: 'policy block_pii')
        @block_injections = Validation.boolean!(block_injections, name: 'policy block_injections')
        @block_secrets = Validation.boolean!(block_secrets, name: 'policy block_secrets')
        @llm_failure_mode = LLM_FAILURE_MODE.call(llm_failure_mode)
        @secret_patterns = PolicyComponents::SecretPatternCollection.call(secret_patterns)
        @rules = PolicyComponents::RuleCollection.call(rules)
        freeze
      end

      # Returns whether PII findings block a decision.
      def block_pii? = @block_pii

      # Returns whether prompt-injection findings block a decision.
      def block_injections? = @block_injections

      # Returns whether secret findings block a decision.
      def block_secrets? = @block_secrets
    end
  end
end
