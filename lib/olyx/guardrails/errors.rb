# frozen_string_literal: true

module Olyx # :nodoc:
  module Guardrails
    # Raised when the Rails integration cannot establish or use valid
    # configuration.
    class ConfigurationError < StandardError; end

    # Raised when an LLM provider fails and the active policy uses
    # <tt>llm_failure_mode: :raise</tt>.
    class LlmProviderError < StandardError; end

    # Raised by explicit Rails enforcement entry points when a decision blocks.
    #
    # Every instance carries a frozen, content-free decision summary. Rescuing
    # Olyx::Guardrails::Blocked also catches low-level secret enforcement
    # because SecretScanner::Blocked is a subclass.
    class Blocked < StandardError
      # The frozen, content-free decision summary that caused the exception.
      attr_reader :decision

      # :call-seq:
      #   new(decision, message = "content blocked by guardrail policy")
      #
      # Builds an exception for +decision+. +message+ is intended for logs and
      # exception reporting; applications should use #decision for structured
      # handling.
      def initialize(decision, message = 'content blocked by guardrail policy')
        @decision = decision
        super(message)
      end
    end
  end
end
