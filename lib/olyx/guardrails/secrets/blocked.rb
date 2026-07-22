# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Raised by SecretScanner.scan! when secret findings make input unsafe.
      class Blocked < StandardError
        attr_reader :findings

        def initialize(findings)
          @findings = findings
          super('Response blocked: secret leakage detected')
        end
      end
    end
  end
end
