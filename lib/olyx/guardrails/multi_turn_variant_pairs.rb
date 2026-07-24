# frozen_string_literal: true

module Olyx
  module Guardrails
    # Matches one multi-turn pattern pair across decoded text variants.
    module MultiTurnVariantPairs
      module_function

      def call(first_variants, second_variants, first_pattern, second_pattern)
        first_variants.product(second_variants).filter_map do |first_text, second_text|
          finding(first_text, second_text, first_pattern, second_pattern)
        end
      end

      def finding(first_text, second_text, first_pattern, second_pattern)
        first_match = first_text.match(first_pattern)
        second_match = second_text.match(second_pattern)
        return unless first_match && second_match

        { role: 'multi-turn', match: "#{first_match[0].strip} / #{second_match[0].strip}" }
      end
      private_class_method :finding
    end
  end
end
