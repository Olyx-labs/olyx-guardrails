# frozen_string_literal: true

if ENV["COVERAGE"] == "true"
  require "coverage"
  Coverage.start(lines: true, branches: true)

  at_exit do
    result = Coverage.result
    library_coverage = result.select { |path, _| path.include?("/lib/") }

    line_totals = library_coverage.values.flat_map { |entry| entry[:lines] }.compact
    branch_totals = library_coverage.values.flat_map do |entry|
      entry[:branches].values.flat_map(&:values)
    end

    line_rate =
      line_totals.empty? ? 100.0 : (line_totals.count(&:positive?) * 100.0 / line_totals.length)
    branch_rate =
      branch_totals.empty? ? 100.0 : (branch_totals.count(&:positive?) * 100.0 / branch_totals.length)

    puts format("Coverage: %.2f%% lines, %.2f%% branches", line_rate, branch_rate)

    # Initial regression floor. Raise these values as additional adversarial
    # paths are covered; the gate prevents coverage from silently disappearing.
    next if line_rate >= 40.0 && branch_rate >= 10.0
    warn "Coverage is below the required 40% line / 10% branch threshold"
    exit(false)
  end
end

require "minitest/autorun"
require "minitest/mock"
require_relative "../lib/olyx/guardrails"
