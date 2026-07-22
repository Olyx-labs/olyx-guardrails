# frozen_string_literal: true

require_relative '../pii_scrubber'

module Olyx
  module Guardrails
    module Checks
      # Decides whether deterministic PII findings are allowed by policy.
      module PiiCheck
        module_function

        def call(source, policy)
          detected = PiiScrubber.scrub(source) != source
          { type: 'pii', allowed: !detected || !policy.block_pii?, detected: detected }
        end
      end
    end
  end
end
