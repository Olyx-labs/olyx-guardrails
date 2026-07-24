# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Builds content-free redaction telemetry.
      module RedactionPayload
        module_function

        def call(result, duration)
          flags(result).merge(evaluation_duration_ms: duration).freeze
        end

        def flags(result)
          identity(result).merge(detections(result))
        end

        def identity(result)
          {
            policy_name: result[:policy_name].to_s[0...100],
            redacted: result[:redacted] == true
          }
        end

        def detections(result)
          {
            pii_detected: result[:pii_detected] == true,
            secret_leaked: result[:secret_leaked] == true,
            policy_violated: result[:policy_violated] == true
          }
        end
        private_class_method :detections, :flags, :identity
      end
    end
  end
end
