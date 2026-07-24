# frozen_string_literal: true

require_relative 'text/detection_variants'
require_relative 'multi_turn_variant_pairs'

module Olyx
  module Guardrails
    # Detects injection patterns inside one user-to-assistant pair.
    module MultiTurnPairScanner
      module_function

      def call(first, second)
        return [] unless valid_transition?(first, second)

        scan(variants(first), variants(second))
      end

      def scan(first_variants, second_variants)
        findings = InjectionPatterns::MULTI_TURN.flat_map do |first_pattern, second_pattern|
          MultiTurnVariantPairs.call(first_variants, second_variants, first_pattern, second_pattern)
        end
        findings.uniq { |finding| finding[:match] }
      end

      def valid_transition?(first, second)
        MessageContent.role(first) == 'user' && MessageContent.role(second) == 'assistant'
      end

      def variants(message)
        Text::DetectionVariants.call(MessageContent.text(message))
      end
      private_class_method :scan, :valid_transition?, :variants
    end
  end
end
