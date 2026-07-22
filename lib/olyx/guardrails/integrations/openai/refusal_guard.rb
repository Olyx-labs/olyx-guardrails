# frozen_string_literal: true

require_relative 'member_reader'

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Converts OpenAI refusal content into the connector error contract.
        module RefusalGuard
          module_function

          def call(content, error_class)
            return unless MemberReader.call(content, :type).to_s == 'refusal'

            raise error_class, message(content)
          end

          def message(content)
            refusal = MemberReader.call(content, :refusal).to_s
            "OpenAI refused the analysis: #{refusal}".gsub(/[\r\n\t]+/, ' ')[0...201]
          end
          private_class_method :message
        end
      end
    end
  end
end
