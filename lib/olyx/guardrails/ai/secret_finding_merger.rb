# frozen_string_literal: true

module Olyx
  module Guardrails
    module Ai
      # Merges the semantic secret flag into a deterministic secret check.
      module SecretFindingMerger
        module_function

        def call(check, analysis, policy)
          return check unless analysis[:secret_leaked]

          count = [check[:count].to_i, 1].max
          check.merge(leaked: true, allowed: !policy.block_secrets?, count: count, ai_flagged: true)
        end
      end
    end
  end
end
