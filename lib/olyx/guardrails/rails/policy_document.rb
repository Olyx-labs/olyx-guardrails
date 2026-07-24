# frozen_string_literal: true

require_relative 'policy_yaml'

module Olyx
  module Guardrails
    module Rails
      # Parses and selects direct or environment-keyed policy YAML.
      class PolicyDocument
        POLICY_KEYS = %w[name max_input_length block_pii block_injections block_secrets llm_failure_mode secret_patterns
                         rules].freeze

        def initialize(path, environment)
          @path = path
          @environment = environment
        end

        def call
          document = PolicyYaml.load(@path)
          return document if direct?(document)

          environment_policy(document)
        end

        private

        def environment_policy(document)
          selected = document[@environment] || document[@environment.to_sym]
          return selected if selected.is_a?(Hash)

          raise ConfigurationError, "guardrail policy file has no #{@environment.inspect} policy: #{@path}"
        end

        def direct?(document)
          document.keys.any? { |key| POLICY_KEYS.include?(key.to_s) }
        end
      end
    end
  end
end
