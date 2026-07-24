# frozen_string_literal: true

require_relative 'pattern_catalog'
require_relative 'private_network_validator'
require_relative 'regexp_finding_source'

module Olyx
  module Guardrails
    module Secrets
      # Finds catalog secrets and validates private-network candidates.
      module CatalogSource
        module_function

        def call(source)
          PatternCatalog::SIMPLE.flat_map { |category, pattern| findings(source, category, pattern) }
        end

        def findings(source, category, pattern)
          matches = RegexpFindingSource.call(source, category, pattern)
          return matches unless category == 'private_network_address'

          matches.select { |finding| PrivateNetworkValidator.call(finding[:full]) }
        end
        private_class_method :findings
      end
    end
  end
end
