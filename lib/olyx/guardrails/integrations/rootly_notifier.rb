# frozen_string_literal: true

require "net/http"
require "json"
require_relative "../pii_scrubber"
require_relative "../secret_scanner"

module Olyx
  module Guardrails
    module Integrations
      # Opens a Rootly incident when a `Olyx::Guardrails.check` result
      # contains a violation. Opt-in: `require` this file separately so
      # projects not using Rootly pay no cost.
      class RootlyNotifier
        ROOTLY_API = "https://api.rootly.com".freeze

        SEVERITY_MAP = [
          [0.75, "sev1"],
          [0.50, "sev2"],
          [0.25, "sev3"],
          [0.0,  "sev4"]
        ].freeze

        # Preview is redacted before truncation, so a secret/PII match that
        # straddles the truncation point still gets caught. The scrub window
        # is generous relative to any pattern's max length but still bounded,
        # so building a preview from a huge input stays cheap.
        PREVIEW_LENGTH       = 300
        PREVIEW_SCRUB_WINDOW = 2_000

        # @param api_key [String] Rootly API bearer token.
        # @param environment [String, nil] included in the incident title
        #   (e.g. `"production"`) when present.
        def initialize(api_key:, environment: nil)
          @api_key     = api_key
          @environment = environment
        end

        # Sends a Rootly incident when the result contains a violation.
        # Never raises — payload-building and delivery failures both
        # degrade to `{ success: false, error: }`, matching the
        # network-failure shape.
        #
        # OPTIMIZE: this makes a synchronous HTTPS call (5s open / 10s read
        #   timeout) on the caller's thread. Calling it inline in a request
        #   path can add up to ~15s of worst-case latency; consider
        #   dispatching from a background job in production. See the
        #   README's Rootly Integration section.
        #
        # @param result [Hash] a result Hash from `Olyx::Guardrails.check`
        #   (or anything with the same `:risk_score`, `:allowed`,
        #   `:injection_attempt`, `:secret_leaked`, `:pii_detected`,
        #   `:checks`, and optional `:ai_analysis` shape).
        # @param input [#to_s, nil] the original input, included in the
        #   incident as a redacted, truncated preview.
        # @param metadata [Hash] extra `key: value` pairs appended verbatim
        #   to the incident summary (e.g. `{ user_id: 42 }`).
        # @return [Hash, nil] `{ success: true, incident_id:, status: }` on
        #   success, `{ success: false, error: }` on any failure, or `nil`
        #   when `result[:risk_score]` is `0` (nothing to report).
        # @example
        #   notifier.notify(result, input: raw_text, metadata: { user_id: 42 })
        def notify(result, input: nil, metadata: {})
          return nil unless result.is_a?(Hash) && result[:risk_score].to_f > 0

          metadata = {} unless metadata.is_a?(Hash)
          payload  = build_payload(result, input: input, metadata: metadata)
          post_incident(payload)
        rescue => e
          { success: false, error: e.message }
        end

        private

        def build_payload(result, input:, metadata:)
          violations = violation_labels(result)
          env_tag    = @environment ? " [#{@environment}]" : ""

          {
            data: {
              type: "incidents",
              attributes: {
                title:         "AI Guardrail Violation#{env_tag}: #{violations.first}",
                summary:       build_summary(result, input, violations, metadata),
                severity_slug: severity_for(result[:risk_score].to_f),
                labels:        [{ name: "ai-safety" }, { name: "olyx-guardrails" }]
              }
            }
          }
        end

        def violation_labels(result)
          labels = []
          labels << "injection attempt" if result[:injection_attempt]
          labels << "secret leaked"     if result[:secret_leaked]
          labels << "PII detected"      if result[:pii_detected]

          length_check = result[:checks]&.find { |c| c[:type] == "length" }
          labels << "input length exceeded" if length_check && !length_check[:allowed]

          labels.empty? ? ["policy violation"] : labels
        end

        def build_summary(result, input, violations, metadata)
          lines = [
            "**Violations:** #{violations.join(', ')}",
            "**Risk score:** #{result[:risk_score]}",
            "**Request blocked:** #{!result[:allowed]}"
          ]

          if (reason = result.dig(:ai_analysis, :reason))
            lines << "**AI analysis:** #{reason}"
          end

          lines << "**Input preview:** #{redacted_preview(input)}" if input

          metadata.each { |k, v| lines << "**#{k}:** #{v}" }

          lines.join("\n")
        end

        # Redacts PII and secrets before truncating, so what leaves the
        # process for a third-party incident tool is never the raw violation
        # content that triggered the alert in the first place.
        def redacted_preview(input)
          raw       = input.to_s[0...PREVIEW_SCRUB_WINDOW]
          scrubbed  = PiiScrubber.scrub(raw)
          scrubbed  = SecretScanner.scan(scrubbed, secret_action: "redact")[:text]
          truncated = scrubbed[0...PREVIEW_LENGTH]
          truncated += "…" if scrubbed.length > PREVIEW_LENGTH || input.to_s.length > PREVIEW_SCRUB_WINDOW
          truncated
        end

        def severity_for(score)
          SEVERITY_MAP.find { |threshold, _| score >= threshold }&.last || "sev4"
        end

        def post_incident(payload)
          uri  = URI("#{ROOTLY_API}/v1/incidents")
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl      = true
          http.open_timeout = 5
          http.read_timeout = 10

          req                  = Net::HTTP::Post.new(uri)
          req["Authorization"] = "Bearer #{@api_key}"
          req["Content-Type"]  = "application/vnd.api+json"
          req["Accept"]        = "application/vnd.api+json"
          req.body             = JSON.generate(payload)

          response = http.request(req)

          {
            success:     response.code.to_i < 300,
            status:      response.code.to_i,
            incident_id: parse_incident_id(response)
          }
        rescue => e
          { success: false, error: e.message }
        end

        def parse_incident_id(response)
          JSON.parse(response.body).dig("data", "id")
        rescue
          nil
        end
      end
    end
  end
end
