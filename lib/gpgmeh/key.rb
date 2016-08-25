# frozen_string_literal: true
require "set"

class GPGMeh
  class Key
    class ParseError < ::GPGMeh::Error; end

    # See README.md for link to gpg documentation on key types
    TYPES = {
      "pub" => "public key",
      "crt" => "X.509 certificate",
      "crs" => "X.509 certificate and private key available",
      "sub" => "subkey",
      "sec" => "secret key",
      "ssb" => "secret subkey",
      "uid" => "user id",
      "uat" => "user attribute",
      "sig" => "signature",
      "rev" => "revocation signature",
      "fpr" => "fingerprint",
      "pkd" => "public key data",
      "grp" => "reserved for gpgsm",
      "rvk" => "revocation key",
      "tru" => "trust database information",
      "spk" => "signature subpacket"
    }.freeze

    TYPES_THAT_MATTER = TYPES.values_at(*%w(pub sub sec ssb rvk)).to_set.freeze

    TRUSTS = {
      "o" => "other",
      "i" => "invalid",
      "d" => "disabled",
      "r" => "revoked",
      "e" => "expired",
      "n" => "none",
      "m" => "marginal",
      "f" => "fully",
      "u" => "ultimately",
      "-" => "unknown",
      "q" => "unknown"
    }.freeze

    CAPABILITIES = {
      "e" => "encrypt",
      "s" => "sign",
      "c" => "certify",
      "a" => "authentication",
      "d" => "disabled"
    }.freeze

    def self.parse(raw_keys)
      raw_keys.split("\n").map do |raw_key|
        fields = raw_key.split(":", 13)
        key = new
        key.type = fields[0]
        next unless TYPES_THAT_MATTER.include?(key.type)
        key.trust = fields[1]
        key.key_length = fields[2].to_i
        key.key_id = fields[4]
        key.creation_date = fields[5]
        key.name = fields[9]
        key.capabilities = fields[11]
        key
      end.compact
    end

    attr_accessor :key_length, :key_id, :name
    attr_reader :type, :trust, :capabilities, :creation_date

    def creation_date=(s)
      @creation_date = Date.parse(s)
    rescue ArgumentError => e
      raise ParseError, "#{e.message}=#{s.inspect}"
    end

    def type=(s)
      @type = TYPES[s] || raise(ParseError, "unkown key type=#{s.inspect}")
    end

    def trust=(s)
      @trust = TRUSTS[s] || raise(ParseError, "unkown trust=#{s.inspect}") unless s.empty?
    end

    def capabilities=(s)
      @capabilities = s.split("").map do |letter|
        CAPABILITIES[letter.downcase] ||
          raise(ParseError, "unkown capability=#{letter.inspect} capabilities=#{s.inspect}")
      end.to_set
    end
  end
end
