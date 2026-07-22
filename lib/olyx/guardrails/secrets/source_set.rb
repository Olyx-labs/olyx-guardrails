# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Combines independent built-in and caller-defined secret sources.
      module SourceSet
        module_function

        def call(source, custom_patterns)
          ConfidentialitySource.call(source) +
            InternalEndpointSource.call(source) +
            CatalogSource.call(source) +
            CustomPatternSource.call(source, custom_patterns)
        end
      end
    end
  end
end
