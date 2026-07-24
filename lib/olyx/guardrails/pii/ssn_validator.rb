# frozen_string_literal: true

module Olyx
  module Guardrails
    module Pii
      # Rejects structurally impossible U.S. Social Security numbers.
      module SsnValidator
        INVALID_AREA = /\A(?:000|666|9\d{2})\z/

        module_function

        def call(ssn)
          area, group, serial = ssn.split(/[- ]/)
          return false unless area && group && serial

          !area.match?(INVALID_AREA) && group != '00' && serial != '0000'
        end
      end
    end
  end
end
