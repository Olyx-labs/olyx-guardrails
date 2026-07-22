# frozen_string_literal: true

require_relative 'finding_order'
require_relative 'rule_matcher'

module Olyx
  module Guardrails
    module PolicyComponents
      # Collects, deduplicates, and orders private policy matches.
      module MatchCollector
        module_function

        def call(source, rules)
          findings = rules.each_with_index.flat_map { |rule, index| RuleMatcher.call(source, rule, index) }
          findings.uniq { |finding| FindingOrder.identity(finding) }.sort_by { |finding| FindingOrder.key(finding) }
        end
      end
    end
  end
end
