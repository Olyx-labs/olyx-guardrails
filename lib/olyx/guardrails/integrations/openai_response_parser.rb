# frozen_string_literal: true

require_relative 'openai/member_reader'
require_relative 'openai/refusal_guard'
require_relative 'openai/response_contents'

module Olyx
  module Guardrails
    module Integrations
      # Extracts a structured schema model from an OpenAI Responses API
      # response while handling both SDK objects and Hash-shaped test doubles.
      class OpenAIResponseParser
        def self.parse(response, error_class:)
          new(response, error_class).parse
        end

        def initialize(response, error_class)
          @response = response
          @error_class = error_class
        end

        def parse
          OpenAIComponents::ResponseContents.call(@response).each do |content|
            OpenAIComponents::RefusalGuard.call(content, @error_class)
            parsed = OpenAIComponents::MemberReader.call(content, :parsed)
            return parsed if parsed
          end

          raise @error_class, 'OpenAI response did not contain parsed structured output'
        end
      end
    end
  end
end
