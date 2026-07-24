# frozen_string_literal: true

require 'active_support/notifications'
require 'forwardable'
require_relative '../guardrails'
require_relative 'rails/active_job_handler'
require_relative 'rails/action_cable'
require_relative 'rails/active_model_validator'
require_relative 'rails/controller'
require_relative 'rails/enforcer'
require_relative 'rails/graphql'
require_relative 'rails/job'
require_relative 'rails/runtime'
require_relative 'rails/upload'

module Olyx # :nodoc:
  module Guardrails
    # Provides opt-in Rails configuration, boundary adapters, instrumentation,
    # and notification delivery.
    #
    # Require this adapter explicitly when Rails is already loaded:
    #
    #   require "olyx/guardrails/rails"
    #
    # Configuration finalizes and freezes during Rails initialization. The
    # adapter never scans controllers, jobs, uploads, GraphQL operations, or
    # Action Cable messages globally; applications include or call the relevant
    # boundary adapter explicitly.
    module Rails
      extend SingleForwardable

      def self.runtime # :nodoc:
        @runtime ||= Runtime.new
      end
      private_class_method :runtime

      # :singleton-method: configuration
      # :call-seq:
      #   Olyx::Guardrails::Rails.configuration -> Configuration
      #
      # Returns the current Rails adapter configuration. The object becomes
      # frozen after finalization.

      # :singleton-method: configure
      # :call-seq:
      #   Olyx::Guardrails::Rails.configure(**options) -> Configuration
      #
      # Replaces the pending Rails configuration with validated +options+.
      # Supported options are +policy+, +policy_path+, +filter_parameters+,
      # +notifier_handlers+, +enabled+, and +llm_provider+.
      #
      # Configure either +policy+ or +policy_path+, never both. Calling this
      # method after finalization raises ConfigurationError.

      # :singleton-method: finalize!
      # :call-seq:
      #   Olyx::Guardrails::Rails.finalize!(environment:) -> Configuration
      #
      # Resolves the policy for +environment+, builds notification handlers,
      # and freezes configuration. The Railtie calls this once after Rails
      # initialization; applications normally do not call it directly.

      # :singleton-method: check
      # :call-seq:
      #   Olyx::Guardrails::Rails.check(input, metadata: {}) -> Hash
      #
      # Evaluates completed +input+ with the finalized policy, publishes
      # content-free instrumentation, and dispatches configured notifications.
      # +metadata+ must be a Hash and is used only by the sanitized notifier.

      # :singleton-method: check_messages
      # :call-seq:
      #   Olyx::Guardrails::Rails.check_messages(messages, metadata: {}) -> Hash
      #
      # Evaluates structured +messages+, including adjacent-turn injection
      # detection, with the finalized Rails configuration.

      # :singleton-method: check_output
      # :call-seq:
      #   Olyx::Guardrails::Rails.check_output(output, metadata: {}) -> Hash
      #
      # Evaluates completed model +output+. Sanitized notification metadata
      # identifies the output direction.

      # :singleton-method: redact
      # :call-seq:
      #   Olyx::Guardrails::Rails.redact(input) -> Hash
      #
      # Redacts completed +input+ with the finalized policy and publishes a
      # content-free redaction event.

      # :singleton-method: redact_output
      # :call-seq:
      #   Olyx::Guardrails::Rails.redact_output(output) -> Hash
      #
      # Redacts completed model +output+ and publishes the standard content-free
      # redaction event.

      def_single_delegators :runtime,
                            :configuration, :configure, :finalize!,
                            :check, :redact, :check_messages,
                            :check_output, :redact_output
    end
  end
end

require_relative 'railtie' if defined?(Rails::Railtie)
