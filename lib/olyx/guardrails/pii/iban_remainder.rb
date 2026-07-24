# frozen_string_literal: true

module Olyx
  module Guardrails
    module Pii
      # Calculates ISO 13616's streaming mod-97 remainder.
      module IbanRemainder
        module_function

        def call(value)
          value.each_char.reduce(0) { |current, character| append(current, digits(character)) }
        end

        def append(current, characters)
          characters.each_char.reduce(current) { |memo, digit| ((memo * 10) + digit.to_i) % 97 }
        end

        def digits(character)
          character.match?(/[A-Z]/) ? (character.ord - 55).to_s : character
        end
        private_class_method :append, :digits
      end
    end
  end
end
