# frozen_string_literal: true

require_relative 'ingress'

module Olyx # :nodoc:
  module Guardrails
    module Rails
      # Adds private, exception-driven helpers to Action Cable channels.
      #
      # +guardrails_check_cable!+ evaluates incoming content.
      # +guardrails_check_cable_output!+ evaluates completed outgoing content.
      # Both accept +metadata:+ and add the channel class name under +:channel+.
      module ActionCable
        include Ingress

        private

        # Evaluates incoming channel content and raises Blocked when rejected.
        alias guardrails_check_cable! guardrails_check_ingress!

        # Evaluates outgoing channel content and raises Blocked when rejected.
        alias guardrails_check_cable_output! guardrails_check_ingress_output!

        def guardrails_ingress_key = :channel
      end
    end
  end
end
