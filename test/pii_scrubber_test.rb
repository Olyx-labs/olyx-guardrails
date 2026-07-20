# frozen_string_literal: true

require_relative "test_helper"

class PiiScrubberTest < Minitest::Test
  def test_scrubs_email
    assert_equal "contact [EMAIL] for details", Olyx::Guardrails::PiiScrubber.scrub("contact user@example.com for details")
  end

  def test_scrubs_ssn
    assert_equal "my ssn is [SSN]", Olyx::Guardrails::PiiScrubber.scrub("my ssn is 123-45-6789")
  end

  def test_scrubs_api_token
    assert_equal "key=[TOKEN]", Olyx::Guardrails::PiiScrubber.scrub("key=sk-abcdefghijklmnop")
  end

  def test_scrubs_bearer_token
    assert_equal "auth=[TOKEN]", Olyx::Guardrails::PiiScrubber.scrub("auth=Bearer abcdefghijklmnop")
  end

  def test_scrubs_ipv4
    assert_equal "host=[IP]", Olyx::Guardrails::PiiScrubber.scrub("host=192.168.1.1")
  end

  def test_passes_clean_text_unchanged
    text = "What is the capital of France?"
    assert_equal text, Olyx::Guardrails::PiiScrubber.scrub(text)
  end

  def test_returns_non_string_unchanged
    assert_equal 42, Olyx::Guardrails::PiiScrubber.scrub(42)
  end

  def test_scrub_messages_with_detection_detects_pii
    messages = [ { "role" => "user", "content" => "email me at test@example.com" } ]
    result = Olyx::Guardrails::PiiScrubber.scrub_messages_with_detection(messages)
    assert result[:detected]
    assert_equal "email me at [EMAIL]", result[:messages].first["content"]
  end

  def test_scrub_messages_with_detection_clean_input
    messages = [ { "role" => "user", "content" => "hello world" } ]
    result = Olyx::Guardrails::PiiScrubber.scrub_messages_with_detection(messages)
    refute result[:detected]
  end

  def test_scrubs_passport_with_context
    result = Olyx::Guardrails::PiiScrubber.scrub("my passport number: AB1234567")
    assert_includes result, "[PASSPORT]"
    refute_includes result, "AB1234567"
  end

  def test_scrubs_iban
    text = "please wire to GB29NWBK60161331926819"
    assert_includes Olyx::Guardrails::PiiScrubber.scrub(text), "[IBAN]"
  end

  def test_scrubs_dob_slash_format
    assert_includes Olyx::Guardrails::PiiScrubber.scrub("DOB: 01/15/1990"), "[DOB]"
  end

  def test_scrubs_dob_spelled_out
    assert_includes Olyx::Guardrails::PiiScrubber.scrub("born on January 15, 1990"), "[DOB]"
  end

  def test_clean_text_without_pii_unchanged
    text = "The weather in Paris is lovely in spring."
    assert_equal text, Olyx::Guardrails::PiiScrubber.scrub(text)
  end

  def test_scrubs_valid_card_number
    assert_equal "card [CARD] on file", Olyx::Guardrails::PiiScrubber.scrub("card 4111111111111111 on file")
  end

  def test_does_not_redact_luhn_invalid_numeric_id
    # 17 digits, outside PHONE_PATTERN's max range (16 digits), so this
    # isolates the CARD_PATTERN + Luhn behavior specifically.
    text = "Reference #12345678901234567 confirmed"
    assert_equal text, Olyx::Guardrails::PiiScrubber.scrub(text)
  end

  def test_card_redaction_preserves_surrounding_whitespace
    result = Olyx::Guardrails::PiiScrubber.scrub("card 4111-1111-1111-1111 was charged")
    assert_equal "card [CARD] was charged", result
  end

  def test_scrubs_phone_with_leading_plus
    assert_equal "call [PHONE] now", Olyx::Guardrails::PiiScrubber.scrub("call +15551234567 now")
  end

  def test_phone_pattern_does_not_grab_substring_of_longer_digit_run
    text = "Reference #12345678901234567 confirmed"
    assert_equal text, Olyx::Guardrails::PiiScrubber.scrub(text)
  end
end
