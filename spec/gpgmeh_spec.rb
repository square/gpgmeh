require "spec_helper"

RSpec.describe GPGMeh do
  it "has a version number" do
    expect(GPGMeh::VERSION).not_to be nil
  end

  describe "public key encryption (.encrypt / .decrypt)" do
    it "encrypts and signs input for a recipient" do
      encrypted_blob = GPGMeh.encrypt("boom", %w(7CAAAB91), sign: true) { |_short_sub_key_id| "test" }
      plaintext = GPGMeh.decrypt(
        encrypted_blob,
        gpg_options: {homedir: SUPPORT.join("spacemanspiff").to_s},
      ) { |_short_sub_key_id| "test" }
      expect(plaintext).to eq("boom")
    end

    it "encrypts input for multiple recipients but does not sign" do
      encrypted_blob = GPGMeh.encrypt("boom", %w(7CAAAB91 243D6FEB), sign: false)

      plaintext_for_spiff = GPGMeh.decrypt(
        encrypted_blob,
        gpg_options: {homedir: SUPPORT.join("spacemanspiff").to_s},
      ) { |_short_sub_key_id| "test" }
      expect(plaintext_for_spiff).to eq("boom")

      plaintext_for_rick = GPGMeh.decrypt(encrypted_blob) { |_short_sub_key_id| "test" }
      expect(plaintext_for_rick).to eq("boom")
    end
  end

  describe "symmetric encryption (.encrypt_symmetric, .decrypt)" do
    it "encrypts and signs input using the specified passphrase" do
      encrypted_blob = GPGMeh.encrypt_symmetric("boom") do |key_id|
        key_id == :symmetric ? "secret" : "test"
      end
      plaintext = GPGMeh.decrypt(
        encrypted_blob,
        gpg_options: {homedir: SUPPORT.join("spacemanspiff").to_s},
      ) { |_| "secret" }
      expect(plaintext).to eq("boom")
    end

    it "encrypts input using the specified passphrase but does not sign" do
      encrypted_blob = GPGMeh.encrypt_symmetric("boom", sign: false) { |_| "secret" }
      plaintext = GPGMeh.decrypt(
        encrypted_blob,
        gpg_options: {homedir: SUPPORT.join("spacemanspiff").to_s},
      ) { |_| "secret" }
      expect(plaintext).to eq("boom")
    end

  end

  describe "errors" do
    it "raises NoPassphraseError if the callback does not return a string" do
      expect {
        GPGMeh.encrypt_symmetric("boom") { |_| nil }
      }.to raise_error(GPGMeh::NoPassphraseError)
    end

    it "raises PassphraseTimeoutError if it takes too long to send the passphrase" do
      expect { GPGMeh.encrypt_symmetric("boom") { |_| nil } }.to raise_error(GPGMeh::NoPassphraseError)
    end
  end

  describe ".public_keys" do
    it "returns a list of public keys" do
      keys = GPGMeh.public_keys
      expect(keys.size).to eq(4)

      expect(keys[0].type).to eq("public key")
      expect(keys[0].key_length).to eq(2048)
      expect(keys[0].key_id).to eq("7A9910E0243D6FEB")
      expect(keys[0].trust).to eq("ultimately")
      expect(keys[0].capabilities).to eq(%w(sign certify encrypt).to_set)
      expect(keys[0].name).to eq("Rick Hardslab <rick@example.com>")
      expect(keys[0].creation_date).to eq(Date.new(2016, 1, 18))

      expect(keys[1].type).to eq("subkey")
      expect(keys[1].key_length).to eq(2048)
      expect(keys[1].key_id).to eq("3DBCA5287FCAE6B3")
      expect(keys[1].trust).to eq("ultimately")
      expect(keys[1].capabilities).to eq(%w(encrypt).to_set)
      expect(keys[1].name).to be_empty
      expect(keys[1].creation_date).to eq(Date.new(2016, 1, 18))

      expect(keys[2].type).to eq("public key")
      expect(keys[2].key_length).to eq(2048)
      expect(keys[2].key_id).to eq("78653ADC7CAAAB91")
      expect(keys[2].trust).to eq("ultimately")
      expect(keys[2].capabilities).to eq(%w(sign encrypt certify).to_set)
      expect(keys[2].name).to eq("Spaceman Spiff <spiff@example.com>")
      expect(keys[2].creation_date).to eq(Date.new(2016, 1, 18))

      expect(keys[3].type).to eq("subkey")
      expect(keys[3].key_length).to eq(2048)
      expect(keys[3].key_id).to eq("922049F511AB415A")
      expect(keys[3].trust).to eq("ultimately")
      expect(keys[3].capabilities).to eq(%w(encrypt).to_set)
      expect(keys[3].name).to be_empty
      expect(keys[3].creation_date).to eq(Date.new(2016, 1, 18))
    end
  end

  describe ".secret_keys" do
    it "returns a list of secret keys" do
      keys = GPGMeh.secret_keys
      expect(keys.size).to eq(2)

      expect(keys[0].type).to eq("secret key")
      expect(keys[0].key_length).to eq(2048)
      expect(keys[0].key_id).to eq("7A9910E0243D6FEB")
      expect(keys[0].trust).to be(nil)
      expect(keys[0].capabilities).to be_empty
      expect(keys[0].name).to eq("Rick Hardslab <rick@example.com>")
      expect(keys[0].creation_date).to eq(Date.new(2016, 1, 18))

      expect(keys[1].type).to eq("secret subkey")
      expect(keys[1].key_length).to eq(2048)
      expect(keys[1].key_id).to eq("3DBCA5287FCAE6B3")
      expect(keys[1].trust).to be(nil)
      expect(keys[1].capabilities).to be_empty
      expect(keys[1].name).to be_empty
      expect(keys[1].creation_date).to eq(Date.new(2016, 1, 18))
    end
  end

  describe "#read_nonblock" do
    it "never reads and times out" do
      gpg = GPGMeh.send(:new)
      r, _w = IO.pipe
      expect { gpg.send(:read_nonblock, r) }.to raise_error(GPGMeh::TimeoutError)
    end

    it "reads partial output and times out" do
      gpg = GPGMeh.send(:new)
      r, w = IO.pipe
      w << "partial"
      expect do
        gpg.send(:read_nonblock, r) do |partial|
          expect(partial).to eq("partial")
        end
      end.to raise_error(GPGMeh::TimeoutError)
    end
  end
end
