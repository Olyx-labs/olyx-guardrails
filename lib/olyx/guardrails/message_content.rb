# frozen_string_literal: true

module Olyx
  module Guardrails
    # Reads role and text from String or content-block chat messages.
    module MessageContent
      module_function

      def text(message)
        content = value(message, 'content')
        return content if content.is_a?(String)
        return content.filter_map { |block| block_text(block) }.join(' ') if content.is_a?(Array)

        ''
      end

      def role(message)
        value(message, 'role').to_s.downcase
      end

      # Redaction preserves a present String key, including explicit nil or false.
      def key(message, name)
        return name if message.key?(name)

        symbol = name.to_sym
        symbol if message.key?(symbol)
      end

      # Reading preserves the existing truthy String-then-Symbol fallback.
      def value(message, name)
        message[name] || message[name.to_sym]
      end

      def block_text(block)
        value(block, 'text') if block.is_a?(Hash)
      end
      private_class_method :block_text, :value
    end
  end
end
