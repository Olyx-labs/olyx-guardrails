# frozen_string_literal: true

module Olyx
  module Guardrails
    module Pii
      # Validates the structure and range of every IPv4 octet.
      module Ipv4Validator
        module_function

        def call(address)
          octets = address.split('.')
          octets.length == 4 && octets.all? { |octet| octet.to_i.between?(0, 255) }
        end
      end
    end
  end
end
