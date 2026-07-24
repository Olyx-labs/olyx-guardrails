# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Patterns for private network coordinates that should not leave a trust boundary.
      module NetworkPatterns
        INTERNAL_SUFFIX = %r{\.internal\b|\.corp\b|\.intranet\b|\.local/|\bvpc\.|\.private\.|\.lan[/:]}i
        PRIVATE_IP = %r{(?:https?://|://|host[=:\s]+|endpoint[=:\s]+|@)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})}i
      end
    end
  end
end
