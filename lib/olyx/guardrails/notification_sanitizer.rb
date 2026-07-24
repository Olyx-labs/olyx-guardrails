# frozen_string_literal: true

require_relative 'notification/key'
require_relative 'notification/preview'
require_relative 'notification/scrubber'

module Olyx # :nodoc:
  module Guardrails
    # Applies the configured confidentiality policy to notification text.
    class NotificationSanitizer
      FIELD_LENGTH = 300

      def initialize(policy)
        @scrubber = Notification::Scrubber.new(policy)
      end

      def field(value, max_length: FIELD_LENGTH)
        @scrubber.call(value).gsub(/[\r\n\t]+/, ' ')[0...max_length]
      end

      def preview(value)
        Notification::Preview.call(value, @scrubber)
      end

      def key(value)
        Notification::Key.call(value, @scrubber)
      end
    end

    private_constant :NotificationSanitizer
  end
end
