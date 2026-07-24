# frozen_string_literal: true

require_relative 'notification_event_builder'
require_relative 'notification/delivery_dispatcher'
require_relative 'notification/notifier_setup'
require_relative 'notification_sanitizer'
require_relative 'notifier_configuration'
require_relative 'validation'

module Olyx # :nodoc:
  module Guardrails
    # Dispatches one sanitized guardrail event to named application callables.
    #
    # Handlers run synchronously and independently; applications can enqueue
    # asynchronous work from a handler. Every handler receives the same deeply
    # frozen event.
    class Notifier
      # :call-seq:
      #   Notifier.new(policy:, handlers:) -> Notifier
      #
      # Builds a notifier using +policy+ for restricted-content and secret
      # sanitization. +handlers+ must be a non-empty Hash of one to twenty named
      # callables. Each callable accepts one immutable event Hash.
      #
      # Invalid policy, handler names, handler counts, or non-callable handlers
      # raise ArgumentError.
      def initialize(policy:, handlers:)
        @policy, @dispatcher = Notification::NotifierSetup.call(policy, handlers)
      end

      # :call-seq:
      #   notifier.notify(result, input: nil, metadata: {}) -> Hash or nil
      #
      # Dispatches one sanitized event when +result+ is a decision Hash with a
      # positive +:risk_score+. Returns +nil+ for a valid zero-risk decision.
      #
      # +input+ optionally supplies source text for a bounded, redacted preview.
      # +metadata+ supplies bounded caller context and must be a Hash.
      #
      # Invalid decision or metadata arguments raise ArgumentError.
      #
      # Handler failures are isolated and returned in the delivery summary.
      # Event-building failures are returned without raising. See
      # docs/OPERATIONS.md#notification-delivery for both result shapes.
      def notify(result, input: nil, metadata: {})
        validate_arguments!(result, metadata)
        return nil if result[:risk_score].zero?

        deliver(result, input, metadata)
      end

      private

      def deliver(result, input, metadata)
        @dispatcher.call(build_event(result, input, metadata))
      rescue StandardError => error
        @dispatcher.failure(error)
      end

      def build_event(result, input, metadata)
        NotificationEventBuilder.call(result, input: input, metadata: metadata, policy: @policy)
      end

      def validate_arguments!(result, metadata)
        Validation.hash!(result, name: 'notification result')
        Validation.hash!(metadata, name: 'notification metadata')
        score = result[:risk_score]
        return if valid_risk_score?(score)

        raise ArgumentError, 'notification result risk_score must be a finite Numeric from 0.0 through 1.0'
      end

      def valid_risk_score?(score)
        score.is_a?(Numeric) && score.finite? && score >= 0.0 && score <= 1.0
      rescue StandardError
        false
      end
    end
  end
end
