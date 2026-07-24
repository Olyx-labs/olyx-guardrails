# frozen_string_literal: true

require_relative 'redaction_payload'

module Olyx
  module Guardrails
    module Rails
      # Builds content-free redaction and delivery telemetry payloads.
      module InstrumentationPayloads
        module_function

        def redaction(result, duration)
          RedactionPayload.call(result, duration)
        end

        def notification(delivery)
          {
            success: delivery[:success] == true,
            delivery_count: Array(delivery[:deliveries]).length
          }.freeze
        end
      end
    end
  end
end
