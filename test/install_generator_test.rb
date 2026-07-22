# frozen_string_literal: true

require 'tmpdir'
require 'rails/generators'
require_relative 'test_helper'
require_relative '../lib/generators/olyx_guardrails/install_generator'
require_relative '../lib/olyx/guardrails/rails/policy_file'

class InstallGeneratorTest < Minitest::Test
  def test_is_discoverable_by_the_documented_namespace
    generator = Rails::Generators.find_by_namespace('olyx_guardrails:install')

    assert_equal OlyxGuardrails::Generators::InstallGenerator, generator
  end

  def test_generates_initializer_and_safe_environment_policy
    Dir.mktmpdir do |directory|
      generator = OlyxGuardrails::Generators::InstallGenerator.new(
        [],
        {},
        destination_root: directory
      )
      generator.invoke_all

      initializer = File.join(directory, 'config/initializers/olyx_guardrails.rb')
      policy = File.join(directory, 'config/olyx_guardrails.yml')

      assert_path_exists initializer
      assert_path_exists policy
      assert_includes File.read(initializer), 'config.policy_path'
      assert_includes File.read(policy), 'production:'
      refute_includes File.read(policy), '<%'

      loaded = Olyx::Guardrails::Rails::PolicyFile.load(policy, environment: :production)

      assert_equal 'production', loaded.name
      assert_predicate loaded, :block_pii?
      assert_predicate loaded, :block_secrets?
      assert_equal :block, loaded.ai_failure_mode
    end
  end
end
