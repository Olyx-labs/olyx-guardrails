# frozen_string_literal: true

require_relative '../validation'
require_relative '../enum_value'
require_relative 'name'
require_relative 'rule_collection'
require_relative 'secret_pattern_collection'

module Olyx
  module Guardrails
    module PolicyComponents
      LLM_FAILURE_MODE = EnumValue.new(
        allowed: %i[allow block raise],
        error: 'policy llm_failure_mode must be allow, block, or raise'
      )
      private_constant :LLM_FAILURE_MODE

      # Validated policy identity and bounded input limit.
      class IdentityConfiguration
        attr_reader :name, :max_input_length

        def initialize(name, max_input_length)
          @name = Name.call(name)
          @max_input_length = Validation.non_negative_integer!(max_input_length, name: 'policy max_input_length')
          freeze
        end
      end

      # Validated built-in blocking switches.
      class BlockingConfiguration
        def initialize(pii, injections, secrets)
          @pii = Validation.boolean!(pii, name: 'policy block_pii')
          @injections = Validation.boolean!(injections, name: 'policy block_injections')
          @secrets = Validation.boolean!(secrets, name: 'policy block_secrets')
          freeze
        end

        def pii? = @pii
        def injections? = @injections
        def secrets? = @secrets
      end

      # Validated provider, secret, and restricted-content configuration.
      class RestrictionConfiguration
        attr_reader :llm_failure_mode, :secret_patterns, :rules

        def initialize(llm_failure_mode, secret_patterns, rules)
          @llm_failure_mode = LLM_FAILURE_MODE.call(llm_failure_mode)
          @secret_patterns = SecretPatternCollection.call(secret_patterns)
          @rules = RuleCollection.call(rules)
          freeze
        end
      end

      # Composes independent immutable policy configuration sections.
      class Configuration
        attr_reader :identity, :blocking, :restrictions

        def initialize(identity:, blocking:, restrictions:)
          @identity = IdentityConfiguration.new(*identity)
          @blocking = BlockingConfiguration.new(*blocking)
          @restrictions = RestrictionConfiguration.new(*restrictions)
          freeze
        end
      end
    end
  end
end
