# frozen_string_literal: true

require_relative '../errors'

module Olyx
  module Guardrails
    module Secrets
      # Raised by SecretScanner.scan! when secret findings make input unsafe.
      # A Guardrails::Blocked subclass so callers can rescue either the
      # specific findings here or the shared Blocked contract uniformly.
      class Blocked < Guardrails::Blocked
        # Decision shape mirrors Rails::ResultSummary's keys so any handler
        # rescuing the shared Blocked contract can read them uniformly, even
        # though this low-level raise site never ran a full policy decision.
        DECISION = {
          policy_name: nil,
          allowed: false,
          risk_score: nil,
          violations: ['secret_leaked'].freeze,
          policy_rules: [].freeze
        }.freeze

        attr_reader :findings

        def initialize(findings)
          @findings = findings
          super(DECISION, 'Response blocked: secret leakage detected')
        end
      end
    end
  end
end
