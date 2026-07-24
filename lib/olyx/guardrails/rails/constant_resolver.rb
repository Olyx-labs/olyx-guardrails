# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Resolves a namespaced constant without inherited lookup.
      module ConstantResolver
        module_function

        def call(name)
          name.split('::').reduce(Object) { |namespace, constant| namespace.const_get(constant, false) }
        rescue NameError
          raise ArgumentError, "configured Active Job class #{name.inspect} is not defined"
        end
      end
    end
  end
end
