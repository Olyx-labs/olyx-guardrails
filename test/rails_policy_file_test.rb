# frozen_string_literal: true

require 'tmpdir'
require_relative 'test_helper'
require_relative '../lib/olyx/guardrails/rails'

class RailsPolicyFileTest < Minitest::Test
  def with_policy_file(content)
    Dir.mktmpdir do |directory|
      path = File.join(directory, 'olyx_guardrails.yml')
      File.write(path, content)
      yield path
    end
  end

  def test_loads_environment_policy_without_erb_or_aliases
    with_policy_file(<<~YAML) do |path|
      test:
        name: rails-test
        block_pii: true
        block_injections: true
        block_secrets: true
        secret_patterns: []
        rules: []
    YAML
      loaded = Olyx::Guardrails::Rails::PolicyFile.load(path, environment: :test)

      assert_equal 'rails-test', loaded.name
      assert_predicate loaded, :block_pii?
    end
  end

  def test_loads_a_direct_policy_document
    with_policy_file("name: direct\nblock_injections: true\n") do |path|
      loaded = Olyx::Guardrails::Rails::PolicyFile.load(path, environment: :production)

      assert_equal 'direct', loaded.name
    end
  end

  def test_rejects_yaml_aliases
    with_policy_file("defaults: &defaults\n  name: unsafe\ntest: *defaults\n") do |path|
      assert_raises(Olyx::Guardrails::ConfigurationError) do
        Olyx::Guardrails::Rails::PolicyFile.load(path, environment: :test)
      end
    end
  end

  def test_rejects_missing_environment
    with_policy_file("production:\n  name: production\n") do |path|
      error = assert_raises(Olyx::Guardrails::ConfigurationError) do
        Olyx::Guardrails::Rails::PolicyFile.load(path, environment: :test)
      end

      assert_includes error.message, 'no "test" policy'
    end
  end

  def test_rejects_missing_file
    assert_raises(Olyx::Guardrails::ConfigurationError) do
      Olyx::Guardrails::Rails::PolicyFile.load('/does/not/exist.yml', environment: :test)
    end
  end

  def test_configuration_rejects_ambiguous_policy_sources_eagerly
    assert_raises(Olyx::Guardrails::ConfigurationError) do
      Olyx::Guardrails::Rails::Configuration.new(
        policy: Olyx::Guardrails::Policy.default,
        policy_path: 'policy.yml'
      )
    end
  end

  def test_configuration_is_immutable_after_finalization
    configuration = Olyx::Guardrails::Rails::Configuration.new(policy: Olyx::Guardrails::Policy.default)
    configuration.finalize!(environment: :test)

    assert_predicate configuration, :finalized?
    assert_predicate configuration, :frozen?
    refute_respond_to configuration, :policy=
  end

  def test_disabled_configuration_fails_closed
    configuration = Olyx::Guardrails::Rails::Configuration.new(enabled: false)
    configuration.finalize!(environment: :test)

    assert_raises(Olyx::Guardrails::ConfigurationError) { configuration.ensure_enabled! }
  end

  def test_registry_rejects_reconfiguration_after_finalization
    registry = Olyx::Guardrails::Rails::ConfigurationRegistry.new
    registry.configure(policy: Olyx::Guardrails::Policy.default)
    registry.finalize!(environment: :test)

    assert_raises(Olyx::Guardrails::ConfigurationError) do
      registry.configure(policy: Olyx::Guardrails::Policy.default)
    end
  end
end
