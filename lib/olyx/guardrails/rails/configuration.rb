# frozen_string_literal: true

require_relative '../notifier'
require_relative '../policy'
require_relative '../validation'
require_relative 'policy_file'
require_relative 'configuration_values'
require_relative 'configuration_finalizer'

module Olyx # :nodoc:
  module Guardrails
    module Rails
      # Holds validated Rails adapter configuration.
      #
      # Most values validate during construction. Loading an
      # environment-specific +policy_path+ is deferred until #finalize!, which
      # runs once during boot and freezes the configuration.
      #
      # Applications read this object through
      # Olyx::Guardrails::Rails.configuration and configure it through
      # Olyx::Guardrails::Rails.configure.
      class Configuration
        # Default parameter names added to <tt>Rails.application.config.filter_parameters</tt>.
        DEFAULT_FILTER_PARAMETERS = %i[prompt system_prompt llm_input].freeze

        # The optional callable used for semantic analysis.
        attr_reader :llm_provider

        # Whether Rails guardrail entry points are enabled.
        attr_reader :enabled

        # The frozen parameter names added to Rails parameter filtering.
        attr_reader :filter_parameters

        # The finalized Notifier, or +nil+ when no handlers are configured.
        attr_reader :notifier

        # The frozen, named notification handler Hash.
        attr_reader :notifier_handlers

        # The active Policy. Before finalization this may be +nil+ when
        # +policy_path+ is configured.
        attr_reader :policy

        # The configured policy file path, or +nil+.
        attr_reader :policy_path

        # :call-seq:
        #   Configuration.new(policy: nil, policy_path: nil,
        #                     filter_parameters: DEFAULT_FILTER_PARAMETERS,
        #                     notifier_handlers: {}, enabled: true,
        #                     llm_provider: nil) -> Configuration
        #
        # Builds pending Rails configuration. +policy+ must be a Policy;
        # +policy_path+ must identify a safe YAML policy file. Supplying both
        # raises ConfigurationError.
        #
        # +filter_parameters+ is an Array of String or Symbol names.
        # +notifier_handlers+ is a Hash of named callables. +enabled+ requires a
        # literal Boolean, and +llm_provider+ must be callable or +nil+.
        def initialize(
          policy: nil,
          policy_path: nil,
          filter_parameters: DEFAULT_FILTER_PARAMETERS,
          notifier_handlers: {},
          enabled: true,
          llm_provider: nil
        )
          assign_policy_source(policy, policy_path, filter_parameters)
          assign_integration_settings(enabled, notifier_handlers, llm_provider)
          @finalized = false
        end

        # :call-seq:
        #   configuration.finalize!(environment:) -> Configuration
        #
        # Resolves the policy for +environment+, builds the notifier, freezes
        # this instance, and returns it. Repeated calls return the same instance.
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

        # Returns whether this configuration has been finalized and frozen.
        def finalized?
          @finalized
        end

        # Returns +nil+ when enabled. Raises ConfigurationError when disabled.
        def ensure_enabled!
          return if @enabled

          raise ConfigurationError, 'Olyx Guardrails Rails integration is disabled'
        end

        private

        def assign_policy_source(policy, policy_path, filter_parameters)
          raise ConfigurationError, 'configure either Rails policy or policy_path, not both' if policy && policy_path

          @policy = policy && ConfigurationValues.policy(policy)
          @policy_path = policy_path && ConfigurationValues.path(policy_path)
          @filter_parameters = ConfigurationValues.filter_parameters(filter_parameters)
        end

        def assign_integration_settings(enabled, notifier_handlers, llm_provider)
          @enabled = Validation.boolean!(enabled, name: 'Rails integration enabled')
          @notifier_handlers = validate_handlers(notifier_handlers)
          @llm_provider = Validation.callable_or_nil!(llm_provider, name: 'Rails integration llm_provider')
        end

        def validate_handlers(value)
          raise ArgumentError, 'Rails notifier_handlers must be a Hash' unless value.is_a?(Hash)

          value.dup.freeze
        end
      end
    end
  end
end
