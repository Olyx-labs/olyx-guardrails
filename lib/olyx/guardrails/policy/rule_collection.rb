# frozen_string_literal: true

require_relative '../policy_rule'
require_relative 'configuration_hash'
require_relative 'rule_normalizer'

module Olyx
  module Guardrails
    module PolicyComponents
      # Normalizes policy rules and enforces unique identifiers.
      module RuleCollection
        module_function

        def call(values)
          validate_collection!(values)

          rules = values.map { |value| RuleNormalizer.call(value) }
          validate_unique_names!(rules)
          rules.freeze
        end

        def validate_collection!(values)
          raise ArgumentError, RuleNormalizer::ERROR unless values.is_a?(Array)
        end

        def validate_unique_names!(rules)
          names = rules.map(&:name)
          raise ArgumentError, 'policy rule names must be unique' unless names.uniq.length == names.length
        end
        private_class_method :validate_collection!, :validate_unique_names!
      end
    end
  end
end
