# frozen_string_literal: true

require "digest"
require_relative "secret_finding_collector"

module Olyx
  module Guardrails
    # Detects leaked secrets, internal endpoints, private network
    # addresses, and vendor token formats in free text, with distinct detect,
    # redact, and exception-driven enforcement operations.
    #
    # REVIEW: vendor token coverage is a fixed list (GitHub, GitLab, Slack,
    #   npm, AWS, Anthropic, SendGrid, JWT). GCP, Azure, Stripe,
    #   PEM-encoded private keys, and generic high-entropy strings are not
    #   covered. See the README Limitations section.
    class SecretScanner
      # Raised by {scan!} when a secret is found. Carries the same safe,
      # masked `findings` shape {scan} returns.
      class Blocked < StandardError
        attr_reader :findings

        def initialize(findings)
          @findings = findings
          super("Response blocked: secret leakage detected")
        end
      end

      # Detects secrets without modifying input or raising.
      #
      # @param text [#to_s] the text to scan.
      # @param custom_patterns [Array<String>] extra regex strings, compiled
      #   case-insensitively. Invalid patterns raise `ArgumentError`.
      # @return [Hash] `:leaked` and safe, masked `:findings`.
      def self.scan(text, custom_patterns: [])
        source   = text.to_s
        findings = SecretFindingCollector.call(source, custom_patterns: custom_patterns)
        { leaked: findings.any?, findings: findings.map { |finding| public_finding(finding) } }
      end

      # Detects and redacts every match. When a confidentiality marker is the
      # only evidence available, the whole input is redacted rather than
      # returning marked confidential content with just its label removed.
      #
      # @param text [#to_s] the text to redact.
      # @param custom_patterns [Array<String>] see {scan}.
      # @return [Hash] `:text`, `:leaked`, and safe, masked `:findings`.
      def self.redact(text, custom_patterns: [])
        source   = text.to_s
        findings = SecretFindingCollector.call(source, custom_patterns: custom_patterns)
        {
          text:     findings.empty? ? source : apply_redactions(source, findings),
          leaked:   findings.any?,
          findings: findings.map { |finding| public_finding(finding) }
        }
      end

      # Detects secrets and raises when any are found.
      #
      # @param text [#to_s] the text to scan.
      # @param custom_patterns [Array<String>] see {scan}.
      # @return [Hash] the same shape as {scan} when no secret is found.
      # @raise [Blocked] when a secret is found.
      def self.scan!(text, custom_patterns: [])
        result = scan(text, custom_patterns: custom_patterns)
        raise Blocked.new(result[:findings]) if result[:leaked]
        result
      end

      # Returns useful correlation data without exposing plaintext credentials.
      private_class_method def self.public_finding(finding)
        full = finding[:full]
        {
          category:    finding[:category],
          matched:     masked_value(full),
          fingerprint: "sha256:#{Digest::SHA256.hexdigest(full)[0, 12]}",
          start:       finding[:start],
          end:         finding[:end]
        }
      end

      private_class_method def self.masked_value(value)
        return "[REDACTED]" if value.length < 12
        "#{value[0, 4]}…#{value[-4, 4]}"
      end

      private_class_method def self.apply_redactions(text, findings)
        return "[REDACTED]" if findings.any? { |finding| finding[:category] == "confidentiality_marker" }

        merged_redaction_spans(findings).reverse_each.with_object(text.dup) do |(start_pos, end_pos), output|
          output[start_pos...end_pos] = "[REDACTED]"
        end
      end

      private_class_method def self.merged_redaction_spans(findings)
        spans = findings.filter_map do |finding|
          start_pos = finding[:start]
          end_pos = finding[:end]
          [start_pos, end_pos] if end_pos > start_pos
        end
        spans.sort.each_with_object([]) { |span, merged| merge_span(merged, span) }
      end

      private_class_method def self.merge_span(merged, span)
        previous = merged.last
        previous_end = previous&.last
        return merged << span unless previous_end && span.first <= previous_end

        previous[1] = [previous_end, span.last].max
      end
    end
  end
end
