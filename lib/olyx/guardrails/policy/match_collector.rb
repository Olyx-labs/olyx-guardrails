# frozen_string_literal: true

require_relative 'finding_order'
require_relative 'rule_matcher'
require_relative '../text/mapped_normalization'

module Olyx
  module Guardrails
    module PolicyComponents
      # Collects, deduplicates, and orders private policy matches.
      module MatchCollector
        module_function

        def call(source, rules)
          return [] if rules.empty?

          normalized = Text::MappedNormalization.new(source)
          findings = rules.each_with_index.flat_map do |rule, index|
            RuleMatcher.call(source, normalized, rule, index)
          end
          findings.uniq { |finding| FindingOrder.identity(finding) }.sort_by { |finding| FindingOrder.key(finding) }
        end
      end
    end
  end
end
