# frozen_string_literal: true

require_relative 'enforcer'

module Olyx
  module Guardrails
    module Rails
      # Checks caller-extracted upload text without owning parsing or storage.
      module Upload
        module_function

        def check(upload, extractor:, metadata: {})
          text = extract(upload, extractor)
          Guardrails::Rails.check(text, metadata: { ingress: 'upload' }.merge(metadata))
        end

        def check!(upload, extractor:, metadata: {})
          text = extract(upload, extractor)
          Enforcer.check!(text, metadata: { ingress: 'upload' }.merge(metadata))
        end

        def extract(upload, extractor)
          raise ArgumentError, 'upload extractor must respond to call' unless extractor.respond_to?(:call)

          text = extractor.call(upload)
          raise ArgumentError, 'upload extractor must return a String' unless text.is_a?(String)

          text
        end
        private_class_method :extract
      end
    end
  end
end
