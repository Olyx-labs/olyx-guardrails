# frozen_string_literal: true

require_relative 'enforcer'
require_relative '../validation'

module Olyx # :nodoc:
  module Guardrails
    module Rails
      # Evaluates caller-extracted upload text.
      #
      # The application remains responsible for file-size limits, type
      # validation, malware scanning, storage, and bounded text extraction.
      module Upload
        # :call-seq:
        #   Upload.check(upload, extractor:, metadata: {}) -> Hash
        #
        # Calls +extractor+ with +upload+ and evaluates the returned String.
        # +metadata+ must be a Hash. The extractor must be callable and return a
        # String; otherwise this method raises ArgumentError.
        def self.check(upload, extractor:, metadata: {})
          text = extract(upload, extractor)
          Validation.hash!(metadata, name: 'guardrail metadata')
          Guardrails::Rails.check(text, metadata: { ingress: 'upload' }.merge(metadata))
        end

        # :call-seq:
        #   Upload.check!(upload, extractor:, metadata: {}) -> Hash
        #
        # Behaves like check, returning an allowed decision or raising Blocked.
        def self.check!(upload, extractor:, metadata: {})
          text = extract(upload, extractor)
          Validation.hash!(metadata, name: 'guardrail metadata')
          Enforcer.check!(text, metadata: { ingress: 'upload' }.merge(metadata))
        end

        def self.extract(upload, extractor) # :nodoc:
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
