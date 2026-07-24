# frozen_string_literal: true

module Olyx
  module Guardrails
    module Secrets
      # Cloud and SaaS provider credential patterns.
      module CloudCredentialPatterns
        AWS_ACCESS_KEY = /\b(AKIA|ASIA|AROA|ABIA|ACCA|AIPA)[A-Z0-9]{16}\b/
        AWS_SECRET_KEY = %r{(?:aws[_\-\s]?(?:secret[_\-\s]?)?(?:access[_\-\s]?)?key|secret[_\-\s]access[_\-\s]key)[\s=:"']+([A-Za-z0-9/+=]{40})\b}i
        STRIPE_KEY = /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|\bwhsec_[A-Za-z0-9]{16,}/
        GOOGLE_KEY = /\bAIza[0-9A-Za-z_-]{35}\b|\bGOCSPX-[0-9A-Za-z_-]{20,}\b/
        AZURE_STORAGE_KEY = %r{(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}}i
      end
    end
  end
end
