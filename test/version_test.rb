# frozen_string_literal: true

require_relative "test_helper"

class VersionTest < Minitest::Test
  def test_version_file_defines_the_release_version
    guardrails = Olyx::Guardrails
    original = guardrails.send(:remove_const, :VERSION)
    load File.expand_path("../lib/olyx/guardrails/version.rb", __dir__)

    assert_match(/\A\d+\.\d+\.\d+\z/, guardrails::VERSION)
  ensure
    guardrails.send(:remove_const, :VERSION) if guardrails.const_defined?(:VERSION, false)
    guardrails.const_set(:VERSION, original) if original
  end
end
