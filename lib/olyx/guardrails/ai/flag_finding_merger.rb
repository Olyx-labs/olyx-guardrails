# frozen_string_literal: true

module Olyx
  module Guardrails
    module Ai
      # Merges one semantic Boolean finding into its deterministic check.
      module FlagFindingMerger
        module_function

        def call(check, flagged, changes)
          flagged ? check.merge(**changes, ai_flagged: true) : check
        end
      end
    end
  end
end
