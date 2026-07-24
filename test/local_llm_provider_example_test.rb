# frozen_string_literal: true

require_relative 'test_helper'
require_relative '../examples/local_llm_provider'

class LocalLlmProviderExampleTest < Minitest::Test
  def test_builds_json_post_request
    provider = LocalLlmProvider.new('http://127.0.0.1:8080/classify')
    request = provider.send(:http_request, '{"text":"safe"}')

    assert_instance_of Net::HTTP::Post, request
    assert_equal 'application/json', request['Content-Type']
    assert_equal '{"text":"safe"}', request.body
  end

  def test_parses_local_classifier_response_into_provider_contract
    response = Net::HTTPOK.new('1.1', '200', 'OK')
    response.define_singleton_method(:body) do
      JSON.generate(injection_attempt: false, risk_score: 0.2)
    end
    provider = LocalLlmProvider.new('http://127.0.0.1:8080/classify')

    analysis = provider.stub(:request, response) { provider.call('safe', {}) }

    refute analysis.fetch('injection_attempt')
    assert_in_delta 0.2, analysis.fetch('risk_score')
  end

  def test_raises_on_non_successful_classifier_response
    response = Net::HTTPServiceUnavailable.new('1.1', '503', 'Unavailable')
    provider = LocalLlmProvider.new('http://127.0.0.1:8080/classify')

    error = assert_raises(RuntimeError) do
      provider.stub(:request, response) { provider.call('safe', {}) }
    end

    assert_equal 'classifier returned HTTP 503', error.message
  end
end
