$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "gpgmeh"
require "logger"
require "pathname"
require "fileutils"

RSpec.configure do |config|
  SUPPORT = Pathname.new(File.expand_path("../support", __FILE__))

  config.before(:suite) do
    GPGMeh.logger = Logger.new("/dev/null")
    GPGMeh.default_homedir = SUPPORT.join("rickhardslab").to_s
    unless SUPPORT.join("rickhardslab", "random_seed").exist?
      FileUtils.cp(SUPPORT.join("random_seed.1"), SUPPORT.join("rickhardslab", "random_seed"))
    end
    unless SUPPORT.join("spacemanspiff", "random_seed").exist?
      FileUtils.cp(SUPPORT.join("random_seed.2"), SUPPORT.join("spacemanspiff", "random_seed"))
    end
  end
end
