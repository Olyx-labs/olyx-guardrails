# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Provider-independent credential and key material patterns.
      module GenericCredentialPatterns
        TOKEN = /\bghp_\w+|\bghs_\w+|\bgho_\w+|\bghr_\w+|\bxoxb-\S+|\bxoxp-\S+|\bxoxs-\S+|\bxoxe-\S+|\bglpat-\w+|\bgldt-\w+|\bnpm_\w+|\bSG\.[A-Za-z0-9._-]{20,}|\bey[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{20,}|\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|\bkey-\S+/i
        JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/
        PRIVATE_KEY = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/m
        DATABASE_URL = %r{\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@[^\s]+}i
      end
    end
  end
end
