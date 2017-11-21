# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "gpgmeh"
require "logger"
require "pathname"
require "fileutils"
require "securerandom"
require "pry"

RSpec.configure do |config|
  SUPPORT = Pathname.new(File.expand_path("../support", __FILE__))
  GPG_VERSION_REGEX = /gpg \(GnuPG\) 1\.4\./

  config.before(:suite) do
    unless SUPPORT.join("rickhardslab", "random_seed").exist?
      FileUtils.cp(SUPPORT.join("random_seed.1"), SUPPORT.join("rickhardslab", "random_seed"))
    end
    unless SUPPORT.join("spacemanspiff", "random_seed").exist?
      FileUtils.cp(SUPPORT.join("random_seed.2"), SUPPORT.join("spacemanspiff", "random_seed"))
    end

    GPGMeh.logger = Logger.new("/dev/null")
    GPGMeh.default_homedir = SUPPORT.join("rickhardslab").to_s
    GPGMeh.timeout_sec = 1

    if ENV.key?("GPG")
      GPGMeh.default_cmd = ENV["GPG"]
    elsif !GPG_VERSION_REGEX.match?(GPGMeh.version) && `which gpg1`.present?
      GPGMeh.default_cmd = "gpg1"
    end
    expect(GPGMeh.version).to match(GPG_VERSION_REGEX)
  end
end
