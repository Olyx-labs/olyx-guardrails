# frozen_string_literal: true

# Run a local classifier sidecar, then:
#   LLM_CLASSIFIER_URL=http://127.0.0.1:8080/classify \
#     ruby -Ilib examples/local_llm_provider.rb "your input"
#
# The sidecar may use any open-source model or inference runtime. It receives
# JSON containing `text` and deterministic `context`, and returns the bounded
# analysis shape documented in docs/API.md. No provider SDK is required by
# this gem.

require 'json'
require 'net/http'
require 'olyx/guardrails'
require 'uri'

# Minimal application-owned adapter for a local JSON classifier endpoint.
class LocalLlmProvider
  def initialize(endpoint)
    @uri = URI(endpoint)
  end

  def call(text, context)
    # Provider responses remain untrusted input; Guardrails validates and bounds
    # the parsed Hash before merging it with deterministic findings.
    response = request(JSON.generate(text: text, context: context))
    raise "classifier returned HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  end

  private

  def request(body)
    # Keep transport limits in the application-owned adapter. The gem does not
    # impose retries, authentication, or a provider-specific HTTP policy.
    Net::HTTP.start(
      @uri.host,
      @uri.port,
      use_ssl: @uri.scheme == 'https',
      open_timeout: 2,
      read_timeout: 10
    ) do |http|
      http.request(http_request(body))
    end
  end

  def http_request(body)
    request = Net::HTTP::Post.new(@uri)
    request['Content-Type'] = 'application/json'
    request.body = body
    request
  end
end

if $PROGRAM_NAME == __FILE__
  # A transport or schema failure becomes a rejected decision in block mode.
  policy = Olyx::Guardrails::Policy.new(llm_failure_mode: :block)
  provider = LocalLlmProvider.new(
    ENV.fetch('LLM_CLASSIFIER_URL', 'http://127.0.0.1:8080/classify')
  )
  input = ARGV.fetch(0, 'Summarize the public release notes')

  result = Olyx::Guardrails.check(input, policy: policy, llm_provider: provider)
  puts JSON.pretty_generate(result)
end
