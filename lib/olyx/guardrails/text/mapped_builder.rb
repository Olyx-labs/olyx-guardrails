# frozen_string_literal: true

require_relative 'normalizer'

module Olyx
  module Guardrails
    module Text
      # Builds normalized text with indexes back to the original String.
      module MappedBuilder
        module_function

        def call(source)
          text = +''
          starts = []
          endings = []
          source.each_char.with_index do |character, index|
            append(text, starts, endings, Normalizer.normalize_character(character), index)
          end
          [text, starts.freeze, endings.freeze]
        end

        def append(text, starts, endings, normalized, index)
          normalized.to_s.each_char do |character|
            text << character
            starts << index
            endings << (index + 1)
          end
        end
        private_class_method :append
      end
    end
  end
end
