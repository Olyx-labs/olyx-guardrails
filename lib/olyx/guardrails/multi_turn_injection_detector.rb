# frozen_string_literal: true

require_relative 'injection_patterns'
require_relative 'message_content'
require_relative 'multi_turn_pair_scanner'

module Olyx
  module Guardrails
    # Detects split attacks across adjacent user-to-assistant turns.
    module MultiTurnInjectionDetector
      module_function

      def call(messages)
        messages.each_cons(2).flat_map { |first, second| MultiTurnPairScanner.call(first, second) }
      end
    end
  end
end
