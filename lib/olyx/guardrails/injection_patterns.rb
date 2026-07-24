# frozen_string_literal: true

module Olyx
  module Guardrails
    # Declarative prompt-injection pattern catalog.
    module InjectionPatterns
      STRUCTURAL = [
        /\[\s*(?:SYSTEM|INST|INSTRUCTION|OVERRIDE)\s*\]/i,
        /<<\s*(?:sys|system|instructions?)\s*>>/i,
        /#{Regexp.escape('<|system|>')}/i,
        /---+\s*(?:new\s+)?instructions?\s*---+/i,
        /={3,}\s*(?:instructions?|override)\s*={3,}/i,
        /###\s*(?:override|instructions?)/i
      ].freeze

      PHRASES = [
        /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?/i,
        /disregard\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|rules?|training)/i,
        /forget\s+(?:all\s+)?(?:your|previous)\s+instructions?/i,
        /your\s+(?:new\s+)?(?:instructions?\s+are|rules?\s+are)/i,
        /(?:override|bypass|ignore)\s+your\s+(?:instructions?|safety|restrictions?|filters?|rules?|training)/i,
        /(?:pretend|act)\s+(?:you\s+are|as\s+if\s+you|as\s+a(?:n?\s+AI)?)/i,
        /you\s+are\s+now\s+(?:a|an|free|DAN|unrestricted)/i,
        /(?:jailbreak|dan\s+mode|developer\s+mode|god\s+mode|unrestricted\s+mode)/i,
        /do\s+anything\s+now/i,
        /you\s+have\s+no\s+(?:restrictions?|limits?|rules?|filters?)/i,
        /without\s+(?:any\s+)?(?:restrictions?|filters?|limits?|rules?|safety)/i,
        /new\s+(?:system\s+)?persona/i,
        /system\s*(?:prompt|message|instruction)\s*:/i,
        /reveal\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)/i,
        /repeat\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)/i
      ].freeze

      SINGLE_MESSAGE = (STRUCTURAL + PHRASES).freeze

      MULTI_TURN = [
        [/hypothetically/i, /no\s+restrictions?/i],
        [/for\s+a\s+story/i, /ignore\s+(?:your\s+)?(?:guidelines?|rules?)/i],
        [/pretend\s+you('re|\s+are)/i, /as\s+(an?\s+)?(?:AI|assistant)\s+without/i],
        [/let'?s?\s+play\s+a\s+game/i, /you\s+(?:must|have\s+to)\s+answer/i]
      ].freeze
    end
  end
end
