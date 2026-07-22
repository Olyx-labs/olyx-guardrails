# frozen_string_literal: true

require 'json'
require_relative 'signal_summary'

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Encodes untrusted input separately from trusted classifier context.
        class InputBuilder
          def self.call(text, context, instructions:)
            new(text, context, instructions).call
          end

          def initialize(text, context, instructions)
            @text = text
            @signals = context.is_a?(Hash) ? context : {}
            @instructions = instructions
          end

          def call
            [
              { role: :system, content: system_content },
              { role: :user, content: @text.to_s }
            ]
          end

          private

          def system_content
            summary = SignalSummary.call(@signals)
            "#{@instructions}\nLocal scanner signals: #{JSON.generate(summary)}"
          end
        end
      end
    end
  end
end
