# frozen_string_literal: true

require_relative 'ingress'

module Olyx
  module Guardrails
    module Rails
      # Opt-in enforcement helpers for Action Cable channel payloads.
      module ActionCable
        include Ingress

        private

        alias guardrails_check_cable! guardrails_check_ingress!
        alias guardrails_check_cable_output! guardrails_check_ingress_output!

        def guardrails_ingress_key = :channel
      end
    end
  end
end
