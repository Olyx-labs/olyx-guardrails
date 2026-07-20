# frozen_string_literal: true

require_relative "rootly_payload_builder"
require_relative "rootly_transport"

module Olyx
  module Guardrails
    module Integrations
      # Opens a Rootly incident when a `Olyx::Guardrails.check` result
      # contains a violation. Opt-in: `require` this file separately so
      # projects not using Rootly pay no cost.
      class RootlyNotifier
        ROOTLY_API = "https://api.rootly.com".freeze

        # @param api_key [String] Rootly API bearer token.
        # @param environment [String, nil] included in the incident title
        #   (e.g. `"production"`) when present.
        def initialize(api_key:, environment: nil)
          unless api_key.is_a?(String) && !api_key.strip.empty?
            raise ArgumentError, "api_key must be a non-empty String"
          end

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
        # @param metadata [Hash] extra `key: value` pairs sanitized, bounded,
        #   and appended to the incident summary (e.g. `{ user_id: 42 }`).
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
        rescue => error
          { success: false, error: error.message }
        end

        private

        def build_payload(result, input:, metadata:)
          RootlyPayloadBuilder.call(
            result,
            input: input,
            metadata: metadata,
            environment: @environment
          )
        end

        def post_incident(payload)
          RootlyTransport.new(api_key: @api_key, endpoint: ROOTLY_API).post(payload)
        end
      end
    end
  end
end
