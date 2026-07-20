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

  def test_connector_rejects_invalid_optional_boundaries
    base_options = {
      model: "gpt-compatible",
      client: FakeClient.new(FakeResponses.new({})),
      schema: FakeSchema
    }

    [
      {client: Object.new},
      {schema: Object.new},
      {request_options: "five seconds"}
    ].each do |invalid|
      assert_raises(ArgumentError) do
        Olyx::Guardrails::Integrations::OpenAIAnalyzer.new(**base_options, **invalid)
      end
    end
  end

  def test_default_schema_and_client_use_the_official_sdk_contract
    analyzer_class = Olyx::Guardrails::Integrations::OpenAIAnalyzer
    original_schema = analyzer_class.const_get(:AnalysisSchema, false) if
      analyzer_class.const_defined?(:AnalysisSchema, false)
    analyzer_class.send(:remove_const, :AnalysisSchema) if original_schema
    original_openai = Object.const_get(:OpenAI, false) if Object.const_defined?(:OpenAI, false)
    Object.send(:remove_const, :OpenAI) if original_openai

    fake_base_model = Class.new do
      def self.required(name, type, doc:)
        fields << [name, type, doc]
      end

      def self.fields
        @fields ||= []
      end
    end
    fake_client = Class.new
    fake_openai = Module.new
    fake_openai.const_set(:BaseModel, fake_base_model)
    fake_openai.const_set(:Boolean, Object.new)
    fake_openai.const_set(:Client, fake_client)
    Object.const_set(:OpenAI, fake_openai)

    analyzer_class.stub(:require_openai_sdk, nil) do
      schema = analyzer_class.analysis_schema

      assert_same schema, analyzer_class.analysis_schema
      assert_operator schema, :<, fake_base_model
      assert_equal 5, schema.fields.length
      assert_instance_of fake_client, analyzer_class.openai_client
    end
  ensure
    if analyzer_class&.const_defined?(:AnalysisSchema, false)
      analyzer_class.send(:remove_const, :AnalysisSchema)
    end
    analyzer_class.const_set(:AnalysisSchema, original_schema) if original_schema
    Object.send(:remove_const, :OpenAI) if Object.const_defined?(:OpenAI, false)
    Object.const_set(:OpenAI, original_openai) if original_openai
  end

  def test_missing_optional_sdk_has_an_actionable_error
    analyzer_class = Olyx::Guardrails::Integrations::OpenAIAnalyzer

    analyzer_class.stub(:require, ->(_name) { raise LoadError }) do
      error = assert_raises(LoadError) { analyzer_class.openai_client }
      assert_match(/add gem "openai"/, error.message)
    end
  end
end
