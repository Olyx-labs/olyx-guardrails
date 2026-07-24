# frozen_string_literal: true

require_relative 'result_summary'
require_relative 'controller_metadata'
require_relative 'enforcer'
require_relative '../validation'

module Olyx # :nodoc:
  module Guardrails
    module Rails
      # Adds private guardrail helpers to an Action Controller class.
      #
      # Include this concern only in controllers that own an AI input or output
      # boundary. It does not scan parameters automatically.
      #
      #   class AiRequestsController < ApplicationController
      #     include Olyx::Guardrails::Rails::Controller
      #
      #     def create
      #       guardrails_check!(params.require(:prompt))
      #     end
      #   end
      module Controller
        private

        # Evaluates +input+ and returns a decision. +metadata+ is merged over
        # bounded request identity metadata.
        def guardrails_check(input, metadata: {})
          Guardrails::Rails.check(input, metadata: request_metadata(metadata))
        end

        # Evaluates +input+, returning an allowed decision or raising Blocked.
        def guardrails_check!(input, metadata: {})
          Enforcer.check!(input, metadata: request_metadata(metadata))
        end

        # Redacts +input+ and returns the core redaction result.
        def guardrails_redact(input)
          Guardrails::Rails.redact(input)
        end

        def request_metadata(metadata)
          Validation.hash!(metadata, name: 'guardrail metadata')
          ControllerMetadata.call(self).merge(metadata)
        end
      end
    end
  end
end
