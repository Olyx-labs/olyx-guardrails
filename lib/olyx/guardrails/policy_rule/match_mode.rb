# frozen_string_literal: true

require_relative '../enum_value'

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Validates how configured terms are interpreted.
      MatchMode = EnumValue.new(
        allowed: %i[substring whole_word regexp],
        error: 'policy rule match must be substring, whole_word, or regexp'
      )
    end
  end
end
