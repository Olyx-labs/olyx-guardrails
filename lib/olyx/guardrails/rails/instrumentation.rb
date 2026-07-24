# frozen_string_literal: true

require 'active_support/notifications'
require_relative 'instrumentation_payloads'
require_relative 'instrumentation_publisher'
require_relative 'result_summary'

module Olyx
  module Guardrails
    module Rails
      # Publishes sanitized, content-free Active Support events.
      module Instrumentation
        module_function

        def publish_check(result, duration)
          InstrumentationPublisher.call(
            'check.olyx_guardrails',
            ResultSummary.call(result).merge(evaluation_duration_ms: duration)
          )
        end

        def publish_violation(result, duration)
          InstrumentationPublisher.call(
            'violation.olyx_guardrails',
            ResultSummary.call(result).merge(evaluation_duration_ms: duration)
          )
        end

        def publish_redaction(result, duration)
          InstrumentationPublisher.call('redact.olyx_guardrails', InstrumentationPayloads.redaction(result, duration))
        end

        def publish_notification(delivery)
          InstrumentationPublisher.call('notification.olyx_guardrails', InstrumentationPayloads.notification(delivery))
        end
      end
    end
  end
end
