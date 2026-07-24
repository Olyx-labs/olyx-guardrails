# frozen_string_literal: true

require_relative 'ingress'

module Olyx # :nodoc:
  module Guardrails
    module Rails
      # Adds private, exception-driven helpers to GraphQL resolvers and
      # mutations.
      #
      # +guardrails_check_graphql!+ evaluates input.
      # +guardrails_check_graphql_output!+ evaluates completed output. Both
      # accept +metadata:+ and add the resolver class name under
      # +:graphql_resolver+.
      module GraphQL
        include Ingress

        private

        # Evaluates GraphQL-bound input and raises Blocked when rejected.
        alias guardrails_check_graphql! guardrails_check_ingress!

        # Evaluates completed GraphQL output and raises Blocked when rejected.
        alias guardrails_check_graphql_output! guardrails_check_ingress_output!

        def guardrails_ingress_key = :graphql_resolver
      end
    end
  end
end
