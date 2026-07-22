# frozen_string_literal: true

require_relative 'member_reader'

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Flattens Responses API output content across SDK and Hash shapes.
        module ResponseContents
          module_function

          def call(response)
            Array(MemberReader.call(response, :output)).flat_map do |output|
              Array(MemberReader.call(output, :content))
            end
          end
        end
      end
    end
  end
end
