# frozen_string_literal: true

require_relative '../validation'
require_relative 'content_scrubber'
require_relative 'hash_key'

module Olyx
  module Guardrails
    module Pii
      # Preserves chat message shape while redacting String content fields.
      module MessageScrubber
        module_function

        def call(messages)
          Validation.array_of!(messages, Hash, name: 'messages')
          results = messages.map { |message| scrub_message(message) }
          { messages: results.map(&:first), detected: results.any?(&:last) }
        end

        def scrub_message(message)
          key = HashKey.call(message, 'content')
          return [message, false] unless key

          redacted, changed = ContentScrubber.call(message[key])
          [changed ? message.merge(key => redacted) : message, changed]
        end
        private_class_method :scrub_message
      end
    end
  end
end
