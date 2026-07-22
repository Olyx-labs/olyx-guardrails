# frozen_string_literal: true

require 'json'

MINIMUM_SCORE = 95.0

report_path = ARGV.fetch(0) do
  abort 'Usage: ruby script/rubycritic_gate.rb PATH_TO_REPORT_JSON'
end
report = JSON.parse(File.read(report_path))
modules = report.fetch('analysed_modules')
failures = []

score = report.fetch('score').to_f
failures << "overall score #{score} is below #{MINIMUM_SCORE}" if score < MINIMUM_SCORE

modules.each do |entry|
  path = entry.fetch('path')
  failures << "#{path} is rated #{entry.fetch('rating')} (A required)" unless entry.fetch('rating') == 'A'
end

abort "RubyCritic strict gate failed:\n- #{failures.join("\n- ")}" if failures.any?

puts "RubyCritic gate passed: score #{score}, all production files rated A"
