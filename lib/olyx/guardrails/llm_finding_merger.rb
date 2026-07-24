# frozen_string_literal: true

module Olyx
  module Guardrails
    # Unions semantic LLM findings into deterministic checks without clearing any.
    module LlmFindingMerger
      FLAG_SETTINGS = {
        pii: %i[pii_detected detected block_pii?],
        injection: %i[injection_attempt injection_attempt block_injections?]
      }.freeze

      module_function

      def call(checks, analysis, policy)
        secret = secret_merge(checks[:secret], analysis, policy)
        checks.merge(flag_merges(checks, analysis, policy)).merge(secret: secret)
      end

      def flag_merges(checks, analysis, policy)
        FLAG_SETTINGS.to_h do |check_name, (finding_name, result_name, blocking_query)|
          changes = { result_name => true, allowed: !policy.public_send(blocking_query) }
          [check_name, merge_if_flagged(checks[check_name], analysis[finding_name], changes)]
        end
      end

      def secret_merge(check, analysis, policy)
        return check unless analysis[:secret_leaked]

        count = [check[:count].to_i, 1].max
        check.merge(leaked: true, allowed: !policy.block_secrets?, count: count, llm_flagged: true)
      end

      def merge_if_flagged(check, flagged, changes)
        flagged ? check.merge(**changes, llm_flagged: true) : check
      end
      private_class_method :flag_merges, :secret_merge, :merge_if_flagged
    end
  end
end
