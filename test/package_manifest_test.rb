# frozen_string_literal: true

require_relative 'test_helper'

class PackageManifestTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  SPECIFICATION = Gem::Specification.load(File.join(ROOT, 'olyx-guardrails.gemspec'))

  CONSUMER_DOCUMENTATION = %w[
    docs/API.md
    docs/OPERATIONS.md
    docs/POLICIES.md
    docs/RAILS.md
    docs/README.md
  ].freeze
  REPOSITORY_ONLY_FILES = %w[
    CODE_OF_CONDUCT.md
    CONTRIBUTING.md
    SECURITY.md
    docs/RELEASING.md
  ].freeze

  def test_manifest_contains_only_existing_files
    missing_files = SPECIFICATION.files.reject do |path|
      File.file?(File.join(ROOT, path))
    end

    assert_empty missing_files
  end

  def test_manifest_includes_consumer_documentation
    missing_documentation = CONSUMER_DOCUMENTATION - SPECIFICATION.files

    assert_empty missing_documentation
  end

  def test_manifest_excludes_repository_only_files
    packaged_repository_files = REPOSITORY_ONLY_FILES & SPECIFICATION.files

    assert_empty packaged_repository_files
  end

  def test_manifest_excludes_development_and_generated_artifacts
    disallowed_files = SPECIFICATION.files.grep(
      %r{\A(?:\.github|coverage|gemfiles|pkg|script|test|tmp|vendor)/|(?:\.gem|\.lock)\z}
    )

    assert_empty disallowed_files
  end

  def test_packaged_markdown_has_no_links_to_excluded_files
    broken_links = packaged_markdown.flat_map { |path| broken_links_in(path) }

    assert_empty broken_links
  end

  private

  def packaged_markdown
    SPECIFICATION.files.grep(/\.md\z/)
  end

  def broken_links_in(path)
    markdown_targets(path).filter_map do |target|
      packaged_target = packaged_target(path, target)
      next if packaged_target.nil? || SPECIFICATION.files.include?(packaged_target)

      "#{path} -> #{target}"
    end
  end

  def markdown_targets(path)
    File.read(File.join(ROOT, path)).scan(/\]\(([^)]+)\)/).flatten
  end

  def packaged_target(source, target)
    return if target.match?(%r{\A(?:[a-z][a-z0-9+.-]*:|#|/)})

    relative_path = target.split('#', 2).first
    source_directory = File.dirname(File.join(ROOT, source))
    File.expand_path(relative_path, source_directory).delete_prefix("#{ROOT}/")
  end
end
