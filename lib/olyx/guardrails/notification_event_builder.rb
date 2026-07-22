# frozen_string_literal: true

require_relative 'notification/deep_freezer'
require_relative 'notification/base_event'
require_relative 'notification/metadata'
require_relative 'notification/violation_labels'
require_relative 'notification_sanitizer'

module Olyx
  # Vendor-neutral AI safety checks and notification events.
  module Guardrails
    # Composes the bounded, immutable, vendor-neutral notification event.
    class NotificationEventBuilder
      SCHEMA_VERSION = 1

      def self.call(result, input:, metadata:, policy:)
        new(result, input, metadata, policy).call
      end

      def initialize(result, input, metadata, policy)
        @result = result
        @input = input
        @metadata = metadata.is_a?(Hash) ? metadata : {}
        @policy = policy
        @sanitizer = NotificationSanitizer.new(policy)
      end

      def call
        event = Notification::BaseEvent.call(
          @result, metadata: @metadata, policy: @policy, sanitizer: @sanitizer, schema_version: SCHEMA_VERSION
        )
        reason = @result.dig(:ai_analysis, :reason)
        event[:ai_reason] = @sanitizer.field(reason) if reason
        event[:input_preview] = @sanitizer.preview(@input) unless @input.nil?
        Notification::DeepFreezer.call(event)
      end
    end

    private_constant :NotificationEventBuilder
  end
end
