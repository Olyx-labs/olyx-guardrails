# frozen_string_literal: true

module Olyx
  module Guardrails
    module Redaction
      # Presents the stable public redaction result contract.
      module PublicResult
        CONTENT_FIELDS = %i[pii_detected secret_leaked policy_violated policy_findings findings].freeze

        module_function

        def call(source, content, policy)
          text = content[:text]
          content.slice(*CONTENT_FIELDS).merge(
            text: text,
            redacted: text != source,
            policy_name: policy.name
          )
        end
      end
    end
  end
end
