# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Merges overlapping policy findings while preserving the first rule.
      module RedactionSpans
        module_function

        def call(findings)
          findings.each_with_object([]) { |finding, spans| append(spans, finding) }
        end

        def append(spans, finding)
          previous = spans.last
          return spans << span(finding) unless overlaps?(previous, finding)

          previous[:end] = [previous[:end], finding[:end]].max
        end

        def overlaps?(previous, finding)
          previous && finding[:start] < previous[:end]
        end

        def span(finding)
          { start: finding[:start], end: finding[:end], replacement: finding[:rule].replacement }
        end
        private_class_method :append, :overlaps?, :span
      end
    end
  end
end
