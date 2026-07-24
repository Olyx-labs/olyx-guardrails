# frozen_string_literal: true

require_relative 'policy/redaction_spans'
require_relative 'policy/unmatched_transformer'

module Olyx
  # Policy-driven safety checks and redaction for Ruby applications.
  module Guardrails
    # Applies offset-aware replacements for private policy findings.
    class PolicyRedactor
      def self.call(source, findings, transform: nil)
        spans = PolicyComponents::RedactionSpans.call(findings)
        return PolicyComponents::UnmatchedTransformer.call(source, spans, transform) if transform

        replace(source, spans)
      end

      def self.replace(source, spans)
        spans.reverse_each.with_object(source.dup) do |span, output|
          output[span[:start]...span[:end]] = span[:replacement]
        end
      end
      private_class_method :replace
    end

    private_constant :PolicyRedactor
  end
end
