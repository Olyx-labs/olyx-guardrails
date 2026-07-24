# frozen_string_literal: true

require_relative 'mapped_builder'

module Olyx
  module Guardrails
    module Text
      # Holds normalized detector text and translates matches to original spans.
      class MappedNormalization
        attr_reader :text

        def initialize(source)
          @source = source
          @text, @starts, @endings = MappedBuilder.call(source)
        end

        def changed?
          @text != @source
        end

        def original_span(starting, ending)
          [@starts.fetch(starting), @endings.fetch(ending - 1)]
        end
      end
    end
  end
end
