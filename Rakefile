# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/testtask'

Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/*_test.rb']
end

namespace :test do
  desc 'Run the test suite with enforced line and branch coverage'
  task :coverage do
    sh({ 'COVERAGE' => 'true' }, 'bundle', 'exec', 'rake', 'test')
  end
end

desc 'Run the complete local quality gate'
task quality: 'test:coverage' do
  sh 'ruby', 'script/documentation_gate.rb'
  sh 'bundle', 'exec', 'ruby', 'script/rdoc_gate.rb'
  sh 'bundle', 'exec', 'rubocop', '--cache', 'false'
  sh 'bundle', 'exec', 'rubycritic', '-f', 'console', '-f', 'json', '-p', 'tmp/rubycritic'
  sh 'ruby', 'script/rubycritic_gate.rb', 'tmp/rubycritic/report.json'
end

desc 'Run the same complete gate expected before a pull request'
task ci: :quality

task default: :test
