# frozen_string_literal: true

require_relative '../notifier'
require_relative '../policy'
require_relative '../validation'
require_relative 'policy_file'
require_relative 'configuration_values'
require_relative 'configuration_finalizer'
require_relative 'integration_configuration'
require_relative 'policy_configuration'

module Olyx
  module Guardrails
    module Rails
      # Mutable-at-boot, immutable-at-runtime Rails adapter configuration.
      class Configuration
        include IntegrationConfiguration
        include PolicyConfiguration

        DEFAULT_FILTER_PARAMETERS = %i[prompt system_prompt ai_input llm_input].freeze

        attr_reader :ai_analyzer, :enabled, :filter_parameters, :notifier,
                    :notifier_handlers, :policy, :policy_path

        def initialize
          @enabled = true
          @filter_parameters = DEFAULT_FILTER_PARAMETERS
          @notifier_handlers = {}.freeze
          @policy = nil
          @policy_path = nil
          @finalized = false
        end

        # Resolves and validates the policy and handlers once at boot.
        def finalize!(environment:)
          return self if finalized?

          @policy, @notifier = ConfigurationFinalizer.call(
            policy: @policy,
            path: @policy_path,
            handlers: @notifier_handlers,
            environment: environment
          )
          @finalized = true
          freeze
        end

        def finalized?
          @finalized
        end

        def ensure_enabled!
          return if @enabled

          raise ConfigurationError, 'Olyx Guardrails Rails integration is disabled'
        end

        private

        def mutable!
          return unless finalized?

          raise ConfigurationError, 'Olyx Guardrails Rails configuration is already finalized'
        end
      end
    end
  end
end
