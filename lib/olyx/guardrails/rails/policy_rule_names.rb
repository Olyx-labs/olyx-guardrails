# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Extracts unique policy rule identifiers for safe telemetry.
      module PolicyRuleNames
        module_function

        def call(result)
          Array(result[:policy_findings]).filter_map { |finding| name(finding) }.uniq.freeze
        end

        def name(finding) = finding[:rule]&.to_s
        private_class_method :name
      end
    end
  end
end
