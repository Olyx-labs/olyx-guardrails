# frozen_string_literal: true

module Olyx
  module Guardrails
    module Text
      # Produces a bounded comparison form for common Unicode evasions.
      module Normalizer
        ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/
        HOMOGLYPHS = {
          'Α' => 'A', 'А' => 'A', 'Β' => 'B', 'В' => 'B', 'Ε' => 'E', 'Е' => 'E',
          'Η' => 'H', 'Н' => 'H', 'Ι' => 'I', 'І' => 'I', 'Κ' => 'K', 'К' => 'K',
          'Μ' => 'M', 'М' => 'M', 'Ν' => 'N', 'О' => 'O', 'Ρ' => 'P', 'Р' => 'P',
          'С' => 'C', 'Τ' => 'T', 'Т' => 'T', 'Χ' => 'X', 'Х' => 'X',
          'а' => 'a', 'е' => 'e', 'і' => 'i', 'о' => 'o', 'р' => 'p', 'с' => 'c',
          'х' => 'x', 'у' => 'y'
        }.freeze

        module_function

        def call(value)
          value.to_s.each_char.filter_map { |character| normalize_character(character) }.join
        end

        def normalize_character(character)
          return if character.match?(ZERO_WIDTH)

          normalized = character.unicode_normalize(:nfkc)
          HOMOGLYPHS.fetch(normalized, normalized)
        rescue Encoding::CompatibilityError, ArgumentError
          character
        end
      end
    end
  end
end
