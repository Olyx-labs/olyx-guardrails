# frozen_string_literal: true

require_relative 'network_patterns'

module Olyx
  module Guardrails
    module Secrets
      # Expands internal-host suffix matches to the complete endpoint token.
      module InternalEndpointSource
        module_function

        def call(source)
          source.to_enum(:scan, NetworkPatterns::INTERNAL_SUFFIX).map do
            finding(source, Regexp.last_match)
          end
        end

        def finding(source, match)
          ending = match.end(0)
          boundary = source[0...match.begin(0)].rindex(/[\s"']/)
          start = boundary ? boundary + 1 : 0
          { category: 'internal_endpoint', full: source[start...ending], start: start, end: ending }
        end
        private_class_method :finding
      end
    end
  end
end
