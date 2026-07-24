# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Compiles bounded regular-expression policy patterns.
      module RegexpCompiler
        TIMEOUT = 0.1

        module_function

        def call(value)
          pattern = build(value)
          raise ArgumentError, 'policy rule patterns must not match empty text' if pattern.match?('')

          pattern
        rescue RegexpError => error
          raise ArgumentError, "invalid policy rule pattern #{value.inspect}: #{error.message}"
        end

        def build(value)
          return Regexp.new(value, Regexp::IGNORECASE, timeout: TIMEOUT) if value.is_a?(String)
          return Regexp.new(value.source, value.options, timeout: TIMEOUT) if value.is_a?(Regexp)

          raise ArgumentError, 'policy rule patterns must contain only Strings or Regexps'
        end
        private_class_method :build
      end
    end
  end
end
