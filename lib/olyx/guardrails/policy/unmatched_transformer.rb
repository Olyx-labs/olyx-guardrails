# frozen_string_literal: true

require_relative 'unmatched_segment_builder'

module Olyx
  module Guardrails
    module PolicyComponents
      # Applies a secondary transformation only outside policy spans.
      module UnmatchedTransformer
        module_function

        def call(source, spans, transform)
          builder = UnmatchedSegmentBuilder.new(source, transform)
          spans.each { |span| builder.append(span) }
          builder.finish
        end
      end
    end
  end
end
