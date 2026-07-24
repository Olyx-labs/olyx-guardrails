# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Compiles bounded, non-empty custom secret patterns.
      module CustomPatternCompiler
        TIMEOUT = 0.1

        module_function

        def call(pattern)
          compiled = Regexp.new(pattern, Regexp::IGNORECASE, timeout: TIMEOUT)
          raise ArgumentError, 'custom patterns must not match empty text' if compiled.match?('')

          compiled
        rescue RegexpError => error
          raise ArgumentError, "invalid custom pattern #{pattern.inspect}: #{error.message}"
        end
      end
    end
  end
end
