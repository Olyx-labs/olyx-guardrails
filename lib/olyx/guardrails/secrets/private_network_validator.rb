# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Rejects private-network candidates with impossible IPv4 octets.
      module PrivateNetworkValidator
        ADDRESS = /\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b/

        module_function

        def call(value)
          address = value[ADDRESS]
          address&.split('.')&.all? { |octet| octet.to_i.between?(0, 255) }
        end
      end
    end
  end
end
