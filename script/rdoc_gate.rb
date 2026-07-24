# frozen_string_literal: true

require 'pathname'
require 'rdoc/rdoc'
require 'rubygems'

# Enforces complete RDoc coverage for the supported Ruby API surface.
module RdocGate
  ROOT = Pathname(__dir__).join('..').expand_path
  SPECIFICATION = Gem::Specification.load(ROOT.join('olyx-guardrails.gemspec').to_s)

  module_function

  def call
    Dir.chdir(ROOT) do
      arguments = ['--coverage-report', *SPECIFICATION.rdoc_options, *SPECIFICATION.require_paths]
      RDoc::RDoc.new.document(arguments)
    end
  end
end

RdocGate.call if $PROGRAM_NAME == __FILE__
