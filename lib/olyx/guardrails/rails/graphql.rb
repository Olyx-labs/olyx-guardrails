# frozen_string_literal: true

require_relative 'ingress'

module Olyx
  module Guardrails
    module Rails
      # Opt-in enforcement helpers for GraphQL resolvers and mutations.
      module GraphQL
        include Ingress

        private

        alias guardrails_check_graphql! guardrails_check_ingress!
        alias guardrails_check_graphql_output! guardrails_check_ingress_output!

        def guardrails_ingress_key = :graphql_resolver
      end
    end
  end
end
