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
      initializer, policy = generate_into(directory)

      assert_path_exists initializer
      assert_path_exists policy
      assert_includes File.read(initializer), 'policy_path:'
      assert_includes File.read(policy), 'production:'
      refute_includes File.read(policy), '<%'

      loaded = Olyx::Guardrails::Rails::PolicyFile.load(policy, environment: :production)

      assert_equal 'production', loaded.name
      assert_predicate loaded, :block_pii?
      assert_predicate loaded, :block_secrets?
      assert_equal :block, loaded.llm_failure_mode
    end
  end

  def test_generated_customization_examples_form_a_valid_policy
    Dir.mktmpdir do |directory|
      _initializer, policy = generate_into(directory)
      source = File.read(policy)
      prefix, production = source.split("production:\n", 2)
      custom_rules = [
        '  rules:',
        '    - name: confidential_projects',
        '      terms:',
        "        - 'Project Falcon'",
        '      match: whole_word',
        '      block: true'
      ].join("\n")
      production = production
                   .sub('  secret_patterns: []', "  secret_patterns:\n    - 'company-token-[a-z0-9]{24}'")
                   .sub('  rules: []', custom_rules)
      customized = "#{prefix}production:\n#{production}"
      File.write(policy, customized)

      loaded = Olyx::Guardrails::Rails::PolicyFile.load(policy, environment: :production)

      assert_equal ['company-token-[a-z0-9]{24}'], loaded.secret_patterns
      assert_equal ['confidential_projects'], loaded.rules.map(&:name)
    end
  end

  private

  def generate_into(directory)
    generator = OlyxGuardrails::Generators::InstallGenerator.new(
      [],
      {},
      destination_root: directory
    )
    generator.invoke_all

    [
      File.join(directory, 'config/initializers/olyx_guardrails.rb'),
      File.join(directory, 'config/olyx_guardrails.yml')
    ]
  end
end
