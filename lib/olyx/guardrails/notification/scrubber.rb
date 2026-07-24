# frozen_string_literal: true

require_relative '../policy_aware_redactor'

module Olyx
  module Guardrails
    module Notification
      # Applies policy-aware redaction to a bounded notification value.
      class Scrubber
        WINDOW = 2_000

        def initialize(policy)
          @policy = policy
        end

        def call(value)
          PolicyAwareRedactor.call(value.to_s[0...WINDOW], policy: @policy)[:text]
        end
      end
    end
  end
end
