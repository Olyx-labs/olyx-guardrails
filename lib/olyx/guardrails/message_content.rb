# frozen_string_literal: true

module Olyx
  module Guardrails
    # Reads role and text from String or content-block chat messages.
    module MessageContent
      module_function

      def text(message)
        content = message['content'] || message[:content]
        return content if content.is_a?(String)
        return content.filter_map { |block| block_text(block) }.join(' ') if content.is_a?(Array)

        ''
      end

      def role(message)
        (message['role'] || message[:role]).to_s.downcase
      end

      def block_text(block)
        block['text'] || block[:text] if block.is_a?(Hash)
      end
      private_class_method :block_text
    end
  end
end
