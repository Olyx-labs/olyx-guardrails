# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Normalizes and merges overlapping secret redaction offsets.
      module RedactionSpans
        module_function

        def call(findings)
          spans = findings.filter_map { |finding| span(finding) }.sort
          spans.each_with_object([]) { |candidate, merged| append(merged, candidate) }
        end

        def span(finding)
          start = finding[:start]
          ending = finding[:end]
          [start, ending] if ending > start
        end

        def append(merged, candidate)
          previous = merged.last
          previous_end = previous&.last
          return merged << candidate unless previous_end && candidate.first <= previous_end

          previous[1] = [previous_end, candidate.last].max
        end
        private_class_method :span, :append
      end
    end
  end
end
