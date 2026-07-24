# frozen_string_literal: true

module Olyx
  module Guardrails
    module Rails
      # Extracts a declared positional or keyword Active Job argument.
      module JobArgument
        module_function

        def call(arguments, selector)
          return arguments.fetch(selector) if selector.is_a?(Integer)

          keyword(arguments, selector)
        end

        def keyword(arguments, selector)
          validate_selector!(selector)

          keywords = keyword_arguments(arguments)
          raise ArgumentError, "guardrail job keyword #{selector.inspect} is missing" unless keywords

          fetch_keyword(keywords, selector)
        end
        private_class_method :keyword

        def fetch_keyword(keywords, selector)
          keywords.fetch(selector) { keywords.fetch(selector.to_s) }
        end

        def keyword_arguments(arguments)
          arguments.reverse.find { |argument| argument.is_a?(Hash) }
        end

        def validate_selector!(selector)
          raise ArgumentError, 'job guardrail selectors must be Integer or Symbol' unless selector.is_a?(Symbol)
        end
        private_class_method :fetch_keyword, :keyword_arguments, :validate_selector!
      end
    end
  end
end
