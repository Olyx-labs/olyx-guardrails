# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Normalizes String/Symbol keyed policy configuration hashes.
      module ConfigurationHash
        module_function

        def call(config)
          raise ArgumentError, 'policy configuration must be a Hash' unless config.is_a?(Hash)

          config.to_h { |key, value| [key.to_sym, value] }
        rescue NoMethodError
          raise ArgumentError, 'policy configuration keys must be Strings or Symbols'
        end
      end
    end
  end
end
