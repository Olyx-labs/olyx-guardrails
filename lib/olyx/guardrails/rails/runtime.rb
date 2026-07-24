# frozen_string_literal: true

require 'forwardable'
require_relative '../message_source'
require_relative '../validation'
require_relative 'configuration_registry'
require_relative 'decision_service'
require_relative 'redaction_service'

module Olyx
  module Guardrails
    module Rails
      # Owns configured Rails input, message, and completed-output operations.
      class Runtime
        extend Forwardable

        def_delegators :@registry, :configuration, :configure, :finalize!

        INPUT_EVALUATION = DecisionService.new(:check)
        MESSAGE_EVALUATION = DecisionService.new(:check_messages, notification_input: MessageSource)
        private_constant :INPUT_EVALUATION, :MESSAGE_EVALUATION

        def initialize
          @registry = ConfigurationRegistry.new
        end

        def check(input, metadata: {})
          INPUT_EVALUATION.call(input, metadata: validate(metadata), configuration: @registry.ready)
        end

        def redact(input)
          RedactionService.call(input, configuration: @registry.ready)
        end

        def check_messages(messages, metadata: {})
          MESSAGE_EVALUATION.call(messages, metadata: validate(metadata), configuration: @registry.ready)
        end

        def check_output(output, metadata: {})
          metadata = { direction: 'output' }.merge(validate(metadata))
          INPUT_EVALUATION.call(output, metadata: metadata, configuration: @registry.ready)
        end

        def redact_output(output)
          RedactionService.call(output, configuration: @registry.ready)
        end

        private

        def validate(metadata)
          Validation.hash!(metadata, name: 'guardrail metadata')
        end
      end
    end
  end
end
