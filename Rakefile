require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rubocop/rake_task"
require "sq/gem_tasks"

RSpec::Core::RakeTask.new(:spec)
RuboCop::RakeTask.new

desc "Run `rake spec rubocop`"
task default: [:spec, :rubocop]
