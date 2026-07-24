# frozen_string_literal: true

require_relative 'redaction_spans'

module Olyx
  module Guardrails
    module Secrets
      # Applies confidentiality-safe redaction to private findings.
      module Redactor
        module_function

        def call(text, findings)
          return '[REDACTED]' if confidential?(findings)

          RedactionSpans.call(findings).reverse_each.with_object(text.dup) do |(start, ending), output|
            output[start...ending] = '[REDACTED]'
          end
        end

        def confidential?(findings)
          findings.any? { |finding| finding[:category] == 'confidentiality_marker' }
        end
        private_class_method :confidential?
      end
    end
  end
end
