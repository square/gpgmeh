$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "gpgmeh"
require "logger"
require "pathname"
require "fileutils"
require "securerandom"
require "pry"

RSpec.configure do |config|
  SUPPORT = Pathname.new(File.expand_path("../support", __FILE__))

  config.before(:suite) do
    GPGMeh.logger = Logger.new("/dev/null")
    GPGMeh.default_cmd = ENV["GPG"] if ENV.key?("GPG")
    GPGMeh.default_homedir = SUPPORT.join("rickhardslab").to_s
    GPGMeh.timeout_sec = 1
    unless SUPPORT.join("rickhardslab", "random_seed").exist?
      FileUtils.cp(SUPPORT.join("random_seed.1"), SUPPORT.join("rickhardslab", "random_seed"))
    end
    unless SUPPORT.join("spacemanspiff", "random_seed").exist?
      FileUtils.cp(SUPPORT.join("random_seed.2"), SUPPORT.join("spacemanspiff", "random_seed"))
    end
    expect(GPGMeh.version.split("\n", 2).first).to match(/1\.4\.\d+/)
  end
end
