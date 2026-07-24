# frozen_string_literal: true

require_relative 'result_summary'

module Olyx # :nodoc:
  module Guardrails
    module Rails
      # Provides explicit exception-driven enforcement for Rails boundaries.
      #
      # Each method returns an allowed decision or raises
      # Olyx::Guardrails::Blocked with a frozen, content-free decision summary.
      module Enforcer
        # :call-seq:
        #   Enforcer.check!(input, metadata: {}) -> Hash
        #
        # Evaluates +input+ through the Rails facade. +metadata+ must be a Hash.
        def self.check!(input, metadata: {})
          enforce(Guardrails::Rails.check(input, metadata: metadata))
        end

        # :call-seq:
        #   Enforcer.check_messages!(messages, metadata: {}) -> Hash
        #
        # Evaluates structured +messages+, including adjacent-turn detection.
        # +metadata+ must be a Hash.
        def self.check_messages!(messages, metadata: {})
          enforce(Guardrails::Rails.check_messages(messages, metadata: metadata))
        end

        # :call-seq:
        #   Enforcer.check_output!(output, metadata: {}) -> Hash
        #
        # Evaluates completed model +output+. +metadata+ must be a Hash.
        def self.check_output!(output, metadata: {})
          enforce(Guardrails::Rails.check_output(output, metadata: metadata))
        end

        def self.enforce(result) # :nodoc:
          return result if result[:allowed]

          raise Blocked, ResultSummary.call(result)
        end
        private_class_method :enforce
      end
    end
  end
end
