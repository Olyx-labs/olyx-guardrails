# frozen_string_literal: true

require_relative 'policy'
require_relative 'notification/handler_collection'

module Olyx
  # Guardrail policy types and evaluation services.
  module Guardrails
    # Validates and freezes the generic notifier's policy and named handlers.
    class NotifierConfiguration
      attr_reader :policy, :handlers

      def initialize(policy:, handlers:)
        @policy = validate_policy(policy)
        @handlers = Notification::HandlerCollection.call(handlers)
        freeze
      end

      private

      def validate_policy(policy)
        return policy if policy.is_a?(Policy)

        raise ArgumentError, 'policy must be an Olyx::Guardrails::Policy'
      end
    end

    private_constant :NotifierConfiguration
  end
end
