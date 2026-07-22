# frozen_string_literal: true

module Olyx
  module Guardrails
    # Derives violation labels that depend on individual check records.
    module SupplementalViolationLabels
      module_function

      def call(result)
        labels = []
        labels << 'input_length_exceeded' if disallowed_check?(result, 'length')
        labels << 'analyzer_error' if disallowed_check?(result, 'ai')
        labels
      end

      def disallowed_check?(result, type)
        Array(result[:checks]).any? { |check| check[:type] == type && !check[:allowed] }
      end
      private_class_method :disallowed_check?
    end
  end
end
