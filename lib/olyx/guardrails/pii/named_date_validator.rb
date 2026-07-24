# frozen_string_literal: true

require 'date'

module Olyx
  module Guardrails
    module Pii
      # Validates English abbreviated or full month dates.
      module NamedDateValidator
        FORMATS = ['%B %d, %Y', '%B %d %Y', '%b %d, %Y', '%b %d %Y'].freeze

        module_function

        def call(value)
          FORMATS.any? { |format| valid?(value.delete('.'), format) }
        end

        def valid?(value, format)
          Date.strptime(value, format)
          true
        rescue Date::Error
          false
        end
        private_class_method :valid?
      end
    end
  end
end
