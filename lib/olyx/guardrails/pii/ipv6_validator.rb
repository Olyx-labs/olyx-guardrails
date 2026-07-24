# frozen_string_literal: true

require 'ipaddr'

module Olyx
  module Guardrails
    module Pii
      # Validates IPv6 candidates with Ruby's address parser.
      module Ipv6Validator
        module_function

        def call(address)
          IPAddr.new(address).ipv6?
        rescue IPAddr::InvalidAddressError
          false
        end
      end
    end
  end
end
