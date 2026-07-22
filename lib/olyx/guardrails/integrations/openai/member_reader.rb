# frozen_string_literal: true

module Olyx
  module Guardrails
    module Integrations
      module OpenAIComponents
        # Reads SDK object and Hash members through one compatibility boundary.
        module MemberReader
          module_function

          def call(object, key)
            return object.public_send(key) if object.respond_to?(key)
            return unless object.is_a?(Hash)

            object.key?(key) ? object[key] : object[key.to_s]
          end
        end
      end
    end
  end
end
