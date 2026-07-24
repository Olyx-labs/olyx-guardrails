# frozen_string_literal: true

require_relative 'checks/injection_check'
require_relative 'checks/length_check'
require_relative 'checks/pii_check'
require_relative 'checks/policy_check'
require_relative 'checks/secret_check'
require_relative 'checks/skipped_checks'

module Olyx
  module Guardrails
    # Coordinates independent deterministic checks for one normalized input.
    class CheckSet
      CHECKS = {
        pii: Checks::PiiCheck,
        injection: Checks::InjectionCheck,
        secret: Checks::SecretCheck,
        policy: Checks::PolicyCheck
      }.freeze

      def self.call(source, policy:)
        length = Checks::LengthCheck.call(source, policy)
        content = length[:allowed] ? scan(source, policy) : Checks::SkippedChecks.call
        content.merge(length: length)
      end

      def self.scan(source, policy)
        CHECKS.to_h { |name, check| [name, check.call(source, policy)] }
      end
      private_class_method :scan
    end
  end
end
