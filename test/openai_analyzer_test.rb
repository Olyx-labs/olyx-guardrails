# frozen_string_literal: true

require_relative "test_helper"
require_relative "../lib/olyx/guardrails/integrations/openai_analyzer"

class OpenAIAnalyzerTest < Minitest::Test
  class FakeSchema
    def self.to_json_schema
      {type: "object"}
    end
  end

  class FakeResponses
    attr_reader :params

    def initialize(response)
      @response = response
    end

    def create(**params)
      @params = params
      @response
    end
  end

  FakeClient = Struct.new(:responses)

  def test_connector_uses_responses_schema_model_and_merges_parsed_result
    parsed = Object.new
    parsed.define_singleton_method(:deep_to_h) do
      {
        injection_attempt: true,
        pii_detected: false,
        secret_leaked: false,
        risk_score: 0.88,
        reason: "indirect instruction override"
      }
    end
    responses = FakeResponses.new(
      output: [{type: "message", content: [{type: "output_text", parsed: parsed}]}]
    )
    analyzer = Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(
      model: "gpt-5.2",
      client: FakeClient.new(responses),
      schema: FakeSchema,
      request_options: {timeout: 5},
      response_options: {temperature: 0.0}
    )

    result = Olyx::Guardrails.check("subtle unsafe request", ai_analyzer: analyzer)

    refute result[:allowed]
    assert result[:injection_attempt]
    assert_in_delta 0.88, result[:risk_score], 0.001
    assert_equal FakeSchema, responses.params[:text]
    assert_equal "gpt-5.2", responses.params[:model]
    assert_equal false, responses.params[:store]
    assert_equal({timeout: 5}, responses.params[:request_options])
    assert_equal 0.0, responses.params[:temperature]
    assert_equal :system, responses.params.dig(:input, 0, :role)
    assert_equal :user, responses.params.dig(:input, 1, :role)
    assert_equal "subtle unsafe request", responses.params.dig(:input, 1, :content)
  end

  def test_connector_records_openai_refusal_as_ai_error
    responses = FakeResponses.new(
      output: [{content: [{type: :refusal, refusal: "Unable to classify"}]}]
    )
    analyzer = Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(
      model: "gpt-5.2",
      client: FakeClient.new(responses),
      schema: FakeSchema
    )

    result = Olyx::Guardrails.check("clean input", ai_analyzer: analyzer)

    assert result[:allowed]
    assert_equal(
      "OpenAI refused the analysis: Unable to classify",
      result.dig(:ai_analysis, :error)
    )
  end

  def test_connector_records_missing_structured_output_as_ai_error
    responses = FakeResponses.new(output: [{content: [{type: "output_text"}]}])
    analyzer = Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(
      model: "gpt-5.2",
      client: FakeClient.new(responses),
      schema: FakeSchema
    )

    result = Olyx::Guardrails.check("clean input", ai_analyzer: analyzer)

    assert_equal(
      "OpenAI response did not contain parsed structured output",
      result.dig(:ai_analysis, :error)
    )
  end

  def test_connector_rejects_reserved_response_options
    error = assert_raises(ArgumentError) do
      Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(
        model: "gpt-5.2",
        client: FakeClient.new(FakeResponses.new({})),
        schema: FakeSchema,
        response_options: {text: Object}
      )
    end

    assert_match(/cannot override: text/, error.message)
  end

  def test_connector_forwards_model_identifiers_without_an_allowlist
    identifiers = [
      "current-general-model",
      "current-mini-model",
      "current-nano-model",
      "model-snapshot-2099-01-01",
      "ft:model:organization:guardrail",
      :model_alias
    ]

    identifiers.each do |identifier|
      responses = FakeResponses.new(
        output: [{content: [{type: "output_text", parsed: {risk_score: 0.0}}]}]
      )
      analyzer = Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(
        model: identifier,
        client: FakeClient.new(responses),
        schema: FakeSchema
      )

      analyzer.call("clean input", {})

      assert_equal identifier, responses.params[:model]
    end
  end

  def test_connector_rejects_empty_or_invalid_model_identifiers
    ["", :"", nil, 123].each do |identifier|
      assert_raises(ArgumentError) do
        Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(
          model: identifier,
          client: FakeClient.new(FakeResponses.new({})),
          schema: FakeSchema
        )
      end
    end
  end
end
