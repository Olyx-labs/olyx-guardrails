# frozen_string_literal: true

module Olyx
  module Guardrails
    module Redaction
      # Applies secret and PII transforms outside policy-owned spans.
      module UnrestrictedText
        module_function

        def call(text, policy)
          secret_safe = SecretScanner.redact(text, custom_patterns: policy.secret_patterns)[:text]
          PiiScrubber.scrub(secret_safe)
        end
      end
    end
  end
end
