# frozen_string_literal: true

require_relative "../pii_scrubber"
require_relative "../secret_scanner"

module Olyx
  module Guardrails
    module Integrations
      # Builds a bounded, redacted Rootly incident payload from a guardrail
      # result. Raw violation content never crosses this boundary.
      class RootlyPayloadBuilder
        SEVERITY_MAP = [
          [0.75, "sev1"],
          [0.50, "sev2"],
          [0.25, "sev3"],
          [0.0, "sev4"]
        ].freeze

        PREVIEW_LENGTH = 300
        SCRUB_WINDOW = 2_000
        FIELD_LENGTH = 300
        METADATA_KEY_LENGTH = 50

        def self.call(result, input:, metadata:, environment:)
          new(result, input, metadata, environment).call
        end

        def initialize(result, input, metadata, environment)
          @result = result
          @input = input
          @metadata = metadata
          @environment = environment
        end

        def call
          violations = violation_labels
          environment = sanitize_field(@environment, max_length: METADATA_KEY_LENGTH)
          env_tag = environment.empty? ? "" : " [#{environment}]"

          {
            data: {
              type: "incidents",
              attributes: {
                title: "AI Guardrail Violation#{env_tag}: #{violations.first}",
                summary: build_summary(violations),
                severity_slug: severity_for(@result[:risk_score].to_f),
                labels: [{ name: "ai-safety" }, { name: "olyx-guardrails" }]
              }
            }
          }
        end

        private

        def violation_labels
          labels = []
          labels << "injection attempt" if @result[:injection_attempt]
          labels << "secret leaked" if @result[:secret_leaked]
          labels << "PII detected" if @result[:pii_detected]

          length_check = @result[:checks]&.find { |check| check[:type] == "length" }
          labels << "input length exceeded" if length_check && !length_check[:allowed]
          labels.empty? ? ["policy violation"] : labels
        end

        def build_summary(violations)
          lines = [
            "**Violations:** #{violations.join(', ')}",
            "**Risk score:** #{@result[:risk_score]}",
            "**Request blocked:** #{!@result[:allowed]}"
          ]

          reason = @result.dig(:ai_analysis, :reason)
          lines << "**AI analysis:** #{sanitize_field(reason)}" if reason
          lines << "**Input preview:** #{redacted_preview}" if @input
          append_metadata(lines)
          lines.join("\n")
        end

        def append_metadata(lines)
          @metadata.each do |key, value|
            safe_key = sanitize_metadata_key(key)
            lines << "**#{safe_key}:** #{sanitize_field(value)}"
          end
        end

        def redacted_preview
          source = @input.to_s
          scrubbed = scrub(source[0...SCRUB_WINDOW])
          truncated = scrubbed[0...PREVIEW_LENGTH]
          truncated += "…" if scrubbed.length > PREVIEW_LENGTH || source.length > SCRUB_WINDOW
          truncated
        end

        def severity_for(score)
          SEVERITY_MAP.find { |threshold, _| score >= threshold }&.last || "sev4"
        end

        def sanitize_field(value, max_length: FIELD_LENGTH)
          scrub(value.to_s[0...SCRUB_WINDOW]).gsub(/[\r\n\t]+/, " ")[0...max_length]
        end

        def scrub(value)
          SecretScanner.redact(PiiScrubber.scrub(value))[:text]
        end

        def sanitize_metadata_key(key)
          normalized = key.to_s.gsub(/[^A-Za-z0-9_.-]/, "_")[0...METADATA_KEY_LENGTH]
          normalized.empty? ? "metadata" : normalized
        end
      end
    end
  end
end
