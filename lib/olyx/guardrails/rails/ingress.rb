# frozen_string_literal: true

require_relative 'enforcer'
require_relative '../validation'

module Olyx
  module Guardrails
    module Rails
      # Shared enforcement behavior for explicit non-controller ingress concerns.
      module Ingress
        private

        def guardrails_check_ingress!(value, metadata: {})
          Enforcer.check!(value, metadata: guardrails_ingress_metadata(metadata))
        end

        def guardrails_check_ingress_output!(value, metadata: {})
          Enforcer.check_output!(value, metadata: guardrails_ingress_metadata(metadata))
        end

        def guardrails_ingress_metadata(metadata)
          Validation.hash!(metadata, name: 'guardrail metadata')
          { guardrails_ingress_key => self.class.name }.merge(metadata)
        end
      end
    end
  end
end
