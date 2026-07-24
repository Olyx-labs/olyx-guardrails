# frozen_string_literal: true

module Olyx
  module Guardrails
    module Pii
      # Finds String or Symbol variants of a Hash key.
      module HashKey
        module_function

        def call(hash, name)
          return name if hash.key?(name)

          symbol = name.to_sym
          symbol if hash.key?(symbol)
        end
      end
    end
  end
end
