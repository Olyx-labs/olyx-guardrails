# frozen_string_literal: true

require_relative "injection_detector"
require_relative "pii_scrubber"
require_relative "secret_scanner"

module Olyx
  module Guardrails
    # Produces the deterministic PII, injection, secret, and length checks for
    # one normalized input.
    class CheckSet
      def self.call(source, **options)
        new(source, **options).call
      end

      def initialize(source, max_input_length:, block_injections:, block_secrets:, custom_patterns:)
        @source = source
        @max_input_length = max_input_length
        @block_injections = block_injections
        @block_secrets = block_secrets
        @custom_patterns = custom_patterns
      end

      def call
        length_check = check_length
        content_checks = length_check[:allowed] ? scanned_content_checks : skipped_content_checks
        content_checks.merge(length: length_check)
      end

      private

      def scanned_content_checks
        {
          pii: check_pii,
          injection: check_injection,
          secret: check_secret
        }
      end

      def skipped_content_checks
        {
          pii: skipped_check("pii", detected: false),
          injection: skipped_check("injection", injection_attempt: false, patterns: []),
          secret: skipped_check("secret", leaked: false, count: 0)
        }
      end

      def check_pii
        detected = PiiScrubber.scrub(@source) != @source
        { type: "pii", allowed: true, detected: detected }
      end

      def check_injection
        scan = InjectionDetector.scan([ { "role" => "user", "content" => @source } ])
        attempt = scan[:injection_attempt]
        {
          type: "injection",
          allowed: !attempt || !@block_injections,
          injection_attempt: attempt,
          patterns: scan[:patterns]
        }
      end

      def check_secret
        scan = SecretScanner.scan(@source, custom_patterns: @custom_patterns)
        leaked = scan[:leaked]
        {
          type: "secret",
          allowed: !leaked || !@block_secrets,
          leaked: leaked,
          count: scan[:findings].size
        }
      end

      def check_length
        length = @source.length
        {
          type: "length",
          allowed: length <= @max_input_length,
          length: length,
          max_length: @max_input_length
        }
      end

      def skipped_check(type, **fields)
        { type: type, allowed: true, skipped: true, **fields }
      end
    end
  end
end
