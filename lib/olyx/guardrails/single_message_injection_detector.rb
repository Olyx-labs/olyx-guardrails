# frozen_string_literal: true

require_relative 'injection_patterns'
require_relative 'message_content'
require_relative 'text/detection_variants'

module Olyx
  module Guardrails
    # Detects injection patterns within one chat message.
    module SingleMessageInjectionDetector
      module_function

      def call(message)
        content = MessageContent.text(message)
        return [] if content.strip.empty?

        role = MessageContent.role(message)
        scan(content, role)
      end

      def scan(content, role)
        findings = Text::DetectionVariants.call(content).flat_map do |variant|
          InjectionPatterns::SINGLE_MESSAGE.filter_map { |pattern| finding(variant, role, pattern) }
        end
        findings.uniq { |finding| finding[:match] }
      end

      def finding(content, role, pattern)
        match = content.match(pattern)
        { role: role.empty? ? 'unknown' : role, match: match[0].strip } if match
      end
      private_class_method :finding, :scan
    end
  end
end
