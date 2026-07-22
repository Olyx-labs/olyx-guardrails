# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Resolves policy sources and constructs the optional notifier at boot.
      module ConfigurationFinalizer
        module_function

        def call(policy:, path:, handlers:, environment:)
          raise ConfigurationError, 'configure either Rails policy or policy_path, not both' if policy && path

          resolved_policy = policy || load_policy(path, environment)
          [resolved_policy, build_notifier(resolved_policy, handlers)]
        end

        def load_policy(path, environment)
          path ? PolicyFile.load(path, environment: environment) : Policy.default
        end

        def build_notifier(policy, handlers)
          Notifier.new(policy: policy, handlers: handlers) unless handlers.empty?
        rescue ArgumentError => error
          raise ConfigurationError, "invalid Rails notifier configuration: #{error.message}"
        end
        private_class_method :load_policy, :build_notifier
      end
    end
  end
end
