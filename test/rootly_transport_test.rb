# frozen_string_literal: true

require_relative "test_helper"
require "olyx/guardrails/integrations/rootly_transport"

class RootlyTransportTest < Minitest::Test
  FakeResponse = Struct.new(:code, :body)

  class FakeHttp
    attr_accessor :use_ssl, :open_timeout, :read_timeout
    attr_reader :request_value

    def initialize(response)
      @response = response
    end

    def request(value)
      @request_value = value
      @response
    end
  end

  def test_posts_json_api_payload_and_parses_incident
    http = FakeHttp.new(FakeResponse.new("201", '{"data":{"id":"incident-123"}}'))
    transport = Olyx::Guardrails::Integrations::RootlyTransport.new(
      api_key: "test-key",
      endpoint: "https://api.example.test"
    )

    Net::HTTP.stub(:new, http) do
      result = transport.post(data: {type: "incidents"})

      assert_equal(
        {success: true, status: 201, incident_id: "incident-123"},
        result
      )
      assert_equal true, http.use_ssl
      assert_equal 5, http.open_timeout
      assert_equal 10, http.read_timeout
      assert_equal "Bearer test-key", http.request_value["Authorization"]
      assert_equal "application/vnd.api+json", http.request_value["Content-Type"]
    end
  end

  def test_non_success_with_invalid_json_has_no_incident_id
    http = FakeHttp.new(FakeResponse.new("500", "not json"))
    transport = Olyx::Guardrails::Integrations::RootlyTransport.new(
      api_key: "test-key",
      endpoint: "http://api.example.test"
    )

    Net::HTTP.stub(:new, http) do
      result = transport.post(data: {type: "incidents"})

      assert_equal false, result[:success]
      assert_equal 500, result[:status]
      assert_nil result[:incident_id]
      assert_equal false, http.use_ssl
    end
  end
end
