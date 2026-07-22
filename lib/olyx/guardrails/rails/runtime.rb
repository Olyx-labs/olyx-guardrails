# frozen_string_literal: true

require 'forwardable'
require_relative 'configuration_registry'
require_relative 'input_runtime'
require_relative 'message_runtime'
require_relative 'output_runtime'

module Olyx
  module Guardrails
    module Rails
      # Composes the independent configuration, input, message, and output runtimes.
      class Runtime
        extend Forwardable

        def_delegators :@registry, :configuration, :configure, :finalize!
        def_delegators :@input, :check, :redact
        def_delegator :@messages, :check_messages
        def_delegators :@output, :check_output, :redact_output

        def initialize
          @registry = ConfigurationRegistry.new
          @input = InputRuntime.new(@registry)
          @messages = MessageRuntime.new(@registry)
          @output = OutputRuntime.new(@registry)
        end
      end
    end
  end
end
