# frozen_string_literal: true

require "json"
require "net/http"

module Olyx
  module Guardrails
    module Integrations
      # Delivers JSON:API incident payloads to Rootly and normalizes the
      # response into the notifier's result contract.
      class RootlyTransport
        def initialize(api_key:, endpoint:)
          @api_key = api_key
          @endpoint = endpoint
        end

        def post(payload)
          uri = URI("#{@endpoint}/v1/incidents")
          response = build_http(uri).request(build_request(uri, payload))
          incident_response(response)
        rescue => error
          { success: false, error: error.message }
        end

        private

        def build_http(uri)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == "https"
          http.open_timeout = 5
          http.read_timeout = 10
          http
        end

        def build_request(uri, payload)
          request = Net::HTTP::Post.new(uri)
          request["Authorization"] = "Bearer #{@api_key}"
          request["Content-Type"] = "application/vnd.api+json"
          request["Accept"] = "application/vnd.api+json"
          request.body = JSON.generate(payload)
          request
        end

        def incident_response(response)
          status = response.code.to_i
          {
            success: status.between?(200, 299),
            status: status,
            incident_id: parse_incident_id(response)
          }
        end

        def parse_incident_id(response)
          JSON.parse(response.body).dig("data", "id")
        rescue StandardError
          nil
        end
      end
    end
  end
end
