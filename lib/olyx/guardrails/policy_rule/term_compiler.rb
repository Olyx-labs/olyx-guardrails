# frozen_string_literal: true

require_relative 'regexp_compiler'

module Olyx
  module Guardrails
    module PolicyRuleComponents
      # Compiles literal terms without exposing regex semantics.
      module TermCompiler
        module_function

        def call(term, mode:)
          validate!(term)
          return RegexpCompiler.call(term) if mode == :regexp

          Regexp.new(source(term, mode), Regexp::IGNORECASE, timeout: RegexpCompiler::TIMEOUT)
        end

        def source(term, mode)
          escaped = Regexp.escape(term)
          mode == :whole_word ? "(?<![[:alnum:]_])#{escaped}(?![[:alnum:]_])" : escaped
        end

        def validate!(term)
          return if term.is_a?(String) && !term.empty?

          raise ArgumentError, 'policy rule terms must contain only non-empty Strings'
        end
        private_class_method :source, :validate!
      end
    end
  end
end
