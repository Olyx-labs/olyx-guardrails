# frozen_string_literal: true

require_relative '../enum_value'

module Olyx
  module Guardrails
    module PolicyComponents
      # Validates analyzer failure behavior.
      AiFailureMode = EnumValue.new(
        allowed: %i[allow block raise],
        error: 'policy ai_failure_mode must be allow, block, or raise'
      )
    end
  end
end
