# frozen_string_literal: true

require_relative '../text/mapped_normalization'

module Olyx
  module Guardrails
    module Secrets
      # Runs secret sources on normalized text and restores original offsets.
      module NormalizedSourceSet
        module_function

        def call(source, custom_patterns)
          mapped = Text::MappedNormalization.new(source)
          return [] unless mapped.changed?

          SourceSet.call(mapped.text, custom_patterns).map { |finding| restore(source, mapped, finding) }
        end

        def restore(source, mapped, finding)
          starting, ending = mapped.original_span(finding[:start], finding[:end])
          finding.merge(full: source[starting...ending], start: starting, end: ending)
        end
        private_class_method :restore
      end
    end
  end
end
