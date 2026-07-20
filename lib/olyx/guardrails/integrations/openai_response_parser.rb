# frozen_string_literal: true

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
          response_contents.each do |content|
            raise_for_refusal(content)
            parsed = read_member(content, :parsed)
            return parsed if parsed
          end

          raise @error_class, "OpenAI response did not contain parsed structured output"
        end

        private

        def response_contents
          Array(read_member(@response, :output)).flat_map do |output|
            Array(read_member(output, :content))
          end
        end

        def raise_for_refusal(content)
          return unless read_member(content, :type).to_s == "refusal"

          refusal = read_member(content, :refusal).to_s
          message = "OpenAI refused the analysis: #{refusal}"
          raise @error_class, bounded_error(message)
        end

        def read_member(object, key)
          return object.public_send(key) if object.respond_to?(key)
          return unless object.is_a?(Hash)

          object.key?(key) ? object[key] : object[key.to_s]
        end

        def bounded_error(message)
          message.to_s.gsub(/[\r\n\t]+/, " ")[0...201]
        end
      end
    end
  end
end
