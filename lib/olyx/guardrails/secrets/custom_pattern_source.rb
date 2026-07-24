# frozen_string_literal: true

require_relative '../validation'
require_relative 'custom_pattern_compiler'
require_relative 'regexp_finding_source'

module Olyx
  module Guardrails
    module Secrets
      # Compiles bounded custom patterns and returns their internal findings.
      module CustomPatternSource
        TIMEOUT_ERROR = defined?(Regexp::TimeoutError) ? Regexp::TimeoutError : RegexpError

        module_function

        def call(source, patterns)
          Validation.array_of!(patterns, String, name: 'custom_patterns')
          patterns.flat_map { |pattern| findings(source, CustomPatternCompiler.call(pattern)) }
        rescue TIMEOUT_ERROR
          raise ArgumentError, 'custom pattern timed out'
        end

        def findings(source, pattern)
          RegexpFindingSource.call(source, 'custom_pattern', pattern).reject { |finding| finding[:full].empty? }
        end
        private_class_method :findings
      end
    end
  end
end
