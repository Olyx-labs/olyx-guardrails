# frozen_string_literal: true

require_relative 'secrets/custom_pattern_source'
require_relative 'secrets/catalog_source'
require_relative 'secrets/confidentiality_source'
require_relative 'secrets/internal_endpoint_source'
require_relative 'secrets/finding_order'
require_relative 'secrets/source_set'
require_relative 'secrets/normalized_source_set'

module Olyx
  module Guardrails
    # Coordinates independent private secret-finding sources.
    class SecretFindingCollector
      def self.call(source, custom_patterns: [])
        new(source.to_s, custom_patterns).call
      end

      def initialize(source, custom_patterns)
        @source = source
        @custom_patterns = custom_patterns
      end

      def call
        findings = Secrets::SourceSet.call(@source, @custom_patterns) +
                   Secrets::NormalizedSourceSet.call(@source, @custom_patterns)
        Secrets::FindingOrder.call(findings)
      end
    end
  end
end
