# frozen_string_literal: true

require_relative 'result_summary'
require_relative 'controller_metadata'
require_relative 'enforcer'

module Olyx
  module Guardrails
    module Rails
      # Explicit Action Controller helpers; no parameters are scanned globally.
      module Controller
        private

        def guardrails_check(input, metadata: {})
          Guardrails::Rails.check(input, metadata: request_metadata(metadata))
        end

        def guardrails_check!(input, metadata: {})
          Enforcer.check!(input, metadata: request_metadata(metadata))
        end

        def guardrails_redact(input)
          Guardrails::Rails.redact(input)
        end

        def request_metadata(metadata)
          raise ArgumentError, 'guardrail metadata must be a Hash' unless metadata.is_a?(Hash)

          ControllerMetadata.call(self).merge(metadata)
        end
      end
    end
  end
end
