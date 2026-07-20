# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      # Validated, immutable request configuration used by {OpenAIAnalyzer}.
      # Kept separate from transport behavior so invalid integration settings
      # fail before a client request can be constructed.
      class OpenAIAnalyzerConfiguration
        RESERVED_RESPONSE_OPTIONS = %i[model input text store request_options].freeze

        attr_reader :model, :client, :schema, :instructions, :store,
          :request_options, :response_options

        def initialize(
          model:, client:, schema:, instructions:, store:, request_options:, response_options:
        )
          @model = validate_model(model)
          @client = validate_client(client)
          @schema = validate_schema(schema)
          @instructions = validate_instructions(instructions)
          @store = validate_store(store)
          @request_options = validate_request_options(request_options)
          @response_options = validate_response_options(response_options).freeze
          freeze
        end

        private

        def validate_model(model)
          valid_string = model.is_a?(String) && !model.strip.empty?
          valid_symbol = model.is_a?(Symbol) && !model.to_s.empty?
          raise ArgumentError, "model must be a non-empty String or Symbol" unless valid_string || valid_symbol

          model
        end

        def validate_client(client)
          unless client.nil? || client.respond_to?(:responses)
            raise ArgumentError, "client must expose responses"
          end

          client
        end

        def validate_schema(schema)
          unless schema.nil? || schema.respond_to?(:to_json_schema)
            raise ArgumentError, "schema must be an OpenAI schema model class"
          end

          schema
        end

        def validate_instructions(instructions)
          valid = instructions.is_a?(String) && !instructions.strip.empty?
          raise ArgumentError, "instructions must be a non-empty String" unless valid

          instructions
        end

        def validate_store(store)
          raise ArgumentError, "store must be true or false" unless [true, false].include?(store)

          store
        end

        def validate_request_options(request_options)
          unless request_options.nil? || request_options.is_a?(Hash)
            raise ArgumentError, "request_options must be a Hash or nil"
          end

          request_options
        end

        def validate_response_options(response_options)
          raise ArgumentError, "response_options must be a Hash" unless response_options.is_a?(Hash)

          validate_response_option_keys!(response_options.keys)
          response_options.to_h { |key, value| [key.to_sym, value] }
        end

        def validate_response_option_keys!(keys)
          valid_keys = keys.all? { |key| key.is_a?(String) || key.is_a?(Symbol) }
          raise ArgumentError, "response_options keys must be Strings or Symbols" unless valid_keys

          reserved = keys.map(&:to_sym) & RESERVED_RESPONSE_OPTIONS
          raise ArgumentError, "response_options cannot override: #{reserved.join(', ')}" unless reserved.empty?
        end
      end
    end
  end
end
