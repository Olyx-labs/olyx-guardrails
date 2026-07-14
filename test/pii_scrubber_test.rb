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
end
