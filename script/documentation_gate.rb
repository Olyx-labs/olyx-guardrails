# frozen_string_literal: true

require 'pathname'
require 'uri'

# Validates local Markdown file links and GitHub-style heading anchors.
module DocumentationGate
  ROOT = Pathname(__dir__).join('..').expand_path
  DOCUMENTS = (ROOT.glob('*.md') + ROOT.glob('docs/*.md')).freeze
  LINK = /!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/
  HEADING = /\A\#{1,6}\s+(.+?)\s*#*\s*\z/
  FENCE = /\A\s*(?:```|~~~)/

  module_function

  def call
    errors = DOCUMENTS.flat_map { |document| errors_for(document) }
    return puts("Documentation gate passed: #{DOCUMENTS.length} files") if errors.empty?

    abort("Documentation gate failed:\n- #{errors.join("\n- ")}")
  end

  def errors_for(document)
    content_lines(document).flat_map do |line, number|
      line.scan(LINK).filter_map do |captures|
        link = captures.first
        validate(document, number, link) if local?(link)
      end
    end
  end

  def local?(link)
    link && !link.match?(/\A(?:https?:|mailto:)/)
  end

  def validate(document, line, link)
    path, fragment = link.split('#', 2)
    target = path.empty? ? document : document.dirname.join(URI.decode_www_form_component(path)).cleanpath
    return location(document, line, "missing #{path}") unless target.file?
    return unless fragment && markdown?(target)
    return if anchors(target).include?(fragment)

    location(document, line, "missing anchor ##{fragment} in #{path.empty? ? document.basename : path}")
  end

  def anchors(document)
    counts = Hash.new(0)
    content_lines(document).filter_map do |line, _number|
      heading = line.match(HEADING)&.captures&.first
      anchor_for(heading, counts) if heading
    end
  end

  def content_lines(document)
    fenced = false

    document.each_line.with_index(1).filter_map do |line, number|
      fenced = !fenced if line.match?(FENCE)
      [line, number] unless fenced || line.match?(FENCE)
    end
  end

  def anchor_for(heading, counts)
    slug = heading.downcase.gsub(/<[^>]*>/, '').gsub(/[^\p{Alnum}\s_-]/, '').strip.gsub(/\s+/, '-')
    index = counts[slug]
    counts[slug] += 1
    index.zero? ? slug : "#{slug}-#{index}"
  end

  def markdown?(path)
    path.extname.casecmp?('.md')
  end

  def location(document, line, message)
    "#{document.relative_path_from(ROOT)}:#{line}: #{message}"
  end
end

DocumentationGate.call if $PROGRAM_NAME == __FILE__
