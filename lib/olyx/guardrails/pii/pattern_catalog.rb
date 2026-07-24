# frozen_string_literal: true

require_relative '../pii_validators'

module Olyx
  module Guardrails
    module Pii
      # Declarative PII pattern, replacement, and validator catalog.
      module PatternCatalog
        EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/
        PHONE = /(?<!\d)(?:(?:\+|00)\d(?:[\s\-.]?\d){7,15}|\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4})(?!\d)/
        SSN = /\b\d{3}[- ]\d{2}[- ]\d{4}\b/
        # Canadian Social Insurance Number: 9 digits, Luhn-checksummed like a
        # card number, so (unlike SSN) it's not gated on a keyword — the
        # checksum alone keeps false positives in line with CARD below.
        SIN = /\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b/
        CARD = /\b\d(?:[ -]?\d){12,18}\b/
        IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/
        IPV6 = /(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])/
        TOKEN = /\b(?:Bearer\s+|sk-|ak_live_|fy-ent-)[A-Za-z0-9._-]{8,}\b/i
        PASSPORT = /\b(?:passport(?:\s+(?:no|number|#))?[\s:]+)([A-Z]{1,2}\d{6,9})\b/i
        IBAN = /\b(?:[A-Z]{2}\d{2}[A-Z0-9]{11,30}|[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)\b/
        DOB = %r{\b(?:dob|date\s+of\s+birth|born\s+on|birthday)[\s:]+(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})}ix

        ENTRIES = [
          [EMAIL, '[EMAIL]'],
          [SSN, '[SSN]', ->(value) { PiiValidators.ssn_valid?(value) }],
          [SIN, '[SIN]', ->(value) { PiiValidators.sin_valid?(value) }],
          [PASSPORT, '[PASSPORT]'],
          [IBAN, '[IBAN]', ->(value) { PiiValidators.iban_valid?(value) }],
          [DOB, '[DOB]', ->(value) { PiiValidators.date_valid?(value) }],
          [IPV4, '[IP]', ->(value) { PiiValidators.ipv4_valid?(value) }],
          [IPV6, '[IP]', ->(value) { PiiValidators.ipv6_valid?(value) }],
          [TOKEN, '[TOKEN]'],
          [CARD, '[CARD]', ->(value) { PiiValidators.luhn_valid?(value) }],
          [PHONE, '[PHONE]']
        ].freeze
      end
    end
  end
end
