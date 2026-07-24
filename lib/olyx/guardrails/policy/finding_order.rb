# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Defines policy finding identity and deterministic ordering.
      module FindingOrder
        module_function

        def identity(finding)
          [finding[:rule].name, finding[:start], finding[:end]]
        end

        def key(finding)
          [finding[:start], finding[:end], finding[:rule_index]]
        end
      end
    end
  end
end
