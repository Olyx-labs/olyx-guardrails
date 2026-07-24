# frozen_string_literal: true

module Olyx
  module Guardrails
    module PolicyComponents
      # Accumulates transformed gaps and fixed policy replacements in source order.
      class UnmatchedSegmentBuilder
        def initialize(source, transform)
          @source = source
          @transform = transform
          @cursor = 0
          @parts = []
        end

        def append(span)
          @parts << @transform.call(@source[@cursor...span[:start]])
          @parts << span[:replacement]
          @cursor = span[:end]
        end

        def finish
          @parts << @transform.call(@source[@cursor..])
          @parts.join
        end
      end
    end
  end
end
