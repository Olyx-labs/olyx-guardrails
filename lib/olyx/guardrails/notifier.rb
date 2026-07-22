# frozen_string_literal: true

require_relative 'notification_event_builder'
require_relative 'notification/delivery_dispatcher'
require_relative 'notification/delivery_summary'
require_relative 'notification/notifier_setup'
require_relative 'notification_sanitizer'
require_relative 'notifier_configuration'

module Olyx
  # Guardrail policy types and evaluation services.
  module Guardrails
    # Dispatches one sanitized guardrail event to named application callables.
    # Handlers run synchronously and independently; applications can enqueue
    # asynchronous work from a handler when required.
    class Notifier
      # @param policy [Policy] the policy used to produce and sanitize results.
      # @param handlers [Hash<String, #call>, Hash<Symbol, #call>] one to 20
      #   named callables accepting the immutable event Hash.
      # @raise [ArgumentError] when policy or handler configuration is invalid.
      def initialize(policy:, handlers:)
        @policy, @dispatcher = Notification::NotifierSetup.call(policy, handlers)
      end

      # Dispatches a sanitized event when the result has non-zero risk.
      # Handler and event-building failures are returned and never raised.
      #
      # @param result [Hash] a result from {Guardrails.check}.
      # @param input [#to_s, nil] original input for a redacted preview.
      # @param metadata [Hash] caller context, capped and policy-redacted.
      # @return [Hash, nil] delivery summary, or nil for zero-risk results.
      def notify(result, input: nil, metadata: {})
        return nil unless deliverable?(result)

        event = build_event(result, input, metadata)
        deliveries = @dispatcher.call(event)
        Notification::DeliverySummary.call(event, deliveries)
      rescue StandardError => error
        @dispatcher.failure(error)
      end

      private

      def build_event(result, input, metadata)
        NotificationEventBuilder.call(result, input: input, metadata: metadata, policy: @policy)
      end

      def deliverable?(result)
        result.is_a?(Hash) && result[:risk_score].to_f.positive?
      end
    end
  end
end
