# frozen_string_literal: true

require 'flog'
require 'yaml'

MAXIMUM_METHOD_SCORE = 10.0
MAXIMUM_CLASS_SCORE = 60.0
EXEMPTION_PATH = File.expand_path('../.flog_exemptions.yml', __dir__)

def owner(method_name)
  return method_name.split('#', 2).first if method_name.include?('#')

  method_name.rpartition('::').first
end

def exemptions
  document = YAML.safe_load_file(EXEMPTION_PATH, aliases: false) || {}
  document.fetch('methods', {})
end

def validate_exemptions!(configured, method_scores)
  stale = configured.keys - method_scores.keys
  abort "Flog gate has stale exemptions: #{stale.join(', ')}" unless stale.empty?

  invalid = configured.reject { |_method, reason| reason.to_s.match?(/dsl|macro|metaprogram/i) }
  abort "Flog exemptions require a DSL/metaprogramming reason: #{invalid.keys.join(', ')}" unless invalid.empty?
end

analyzer = Flog.new
analyzer.flog(*Dir['lib/**/*.rb'])
method_scores = analyzer.totals.reject { |name, _score| name.end_with?('#none') }
configured = exemptions
validate_exemptions!(configured, method_scores)

ordinary_scores = method_scores.reject { |name, _score| configured.key?(name) }
method_failures = ordinary_scores.select { |_name, score| score > MAXIMUM_METHOD_SCORE }
class_scores = ordinary_scores.each_with_object(Hash.new(0.0)) do |(name, score), totals|
  totals[owner(name)] += score
end
class_failures = class_scores.select { |_name, score| score > MAXIMUM_CLASS_SCORE }

failures = method_failures.map { |name, score| "#{name} scores #{score.round(2)} (max #{MAXIMUM_METHOD_SCORE})" }
failures.concat(class_failures.map { |name, score| "#{name} totals #{score.round(2)} (max #{MAXIMUM_CLASS_SCORE})" })
abort "Flog strict gate failed:\n- #{failures.join("\n- ")}" unless failures.empty?

method_peak = ordinary_scores.max_by { |_name, score| score }
class_peak = class_scores.max_by { |_name, score| score }
puts "Flog strict gate passed: max method #{method_peak.last.round(2)} (#{method_peak.first}), " \
     "max class #{class_peak.last.round(2)} (#{class_peak.first}), #{configured.length} DSL exemption(s)"
