# frozen_string_literal: true

require_relative 'pattern_catalog'
require_relative 'regexp_finding_source'

module Olyx
  module Guardrails
    module Secrets
      # Finds explicit confidentiality markers.
      module ConfidentialitySource
        module_function

        def call(source)
          PatternCatalog::CONFIDENTIALITY.flat_map do |pattern|
            RegexpFindingSource.call(source, 'confidentiality_marker', pattern)
          end
        end
      end
    end
  end
end
