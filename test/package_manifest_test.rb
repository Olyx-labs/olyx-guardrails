# frozen_string_literal: true

require_relative 'test_helper'

class PackageManifestTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  SPECIFICATION = Gem::Specification.load(File.join(ROOT, 'olyx-guardrails.gemspec'))

  CORE_FILES = %w[
    CHANGELOG.md
    LICENSE
    README.md
  ].freeze
  EXPECTED_FILES = (
    Dir[File.join(ROOT, 'lib/**/*.rb'), File.join(ROOT, 'lib/generators/**/*.tt')]
      .map { |path| path.delete_prefix("#{ROOT}/") } +
    CORE_FILES
  ).sort.freeze

  def test_manifest_is_exact_consumer_surface
    assert_equal EXPECTED_FILES, SPECIFICATION.files
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
