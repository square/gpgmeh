# GPGMeh: GPG Made Even _HARDER_!

## Why?

GPG can be complicated: this gem is just a high level wrapper around `gpg`.
GPGME also provides a nice API on top of GPG, but it has two drawbacks: it is
not thread safe and it holds the GIL when shelling out to `gpg`. This holds up
the entire ruby process for the duration of the GPG call, which can be
relatively slow.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'gpgmeh'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install gpgmeh

## Usage

### Default Configuration

```ruby
GPGMeh.default_cmd = "gpg" # first gpg found in your $PATH
GPGMeh.default_args = ["--armor", "--trust-model", "always"]` # --no-tty` and `--quiet` are always added to the argument list
GPGMeh.passphrase_timeout_sec = 0.2 # wait up to 200ms for all passphrases to get sent
```

### Public Key Encryption: Rick wants to encrypt and sign something for Spiff

```ruby
# 7CAAAB91 is Spaceman Spiff's public key id; multiple recipients can be specified
GPGMeh.encrypt("boom", ["7CAAAB91"]) do |key_id|
  # This is the passphrase callback. The argument is Rick's secret key id.
  # Return value: the secret keyring passphrase
  "rick's-secret-keyring-passphrase"
end
```

### Public Key Decryption: Spiff wants to decrypt something from Rick

```ruby
encrypted_message = <<EOM
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

hQEMA5IgSfURq0FaAQf/TxrcB0EeC5XpEwVyjaKoMNR7d2PZFBLQL9wX81jEIPIN
0tsq7/OSj/bZF1p9gkQ9YN+wzvS+1pLlPo1T/GNGrt6ay+ml4mOjezACfrQ+EBB+
ay5XrDbwemAW/tqLMkJMrx28dt8fkNlXv+uzPKpQI5cubBcDyoD/E53rqyybjt+D
pqA9bZ3OORqWHPBZy50eaTs/tyVgBpfXsgcTfbwSedSNnLXxdB0p2pKgPjeAYlCm
DGzxIRSSZjHSBieDm6ZUv/tcplXqrzQxZT/0rhneoG5FK+0g5sayEPQKozdVdFM3
B4a2jzcDbhkNEZ2HV2VVmRp2HHaFRFftuPeoECQGjckoxTo5u9K6cnOymDbf2lN0
/0Jec1LUDWLYUtzNonBpPdlUIxlllT6Q0Q==
=ANji
-----END PGP MESSAGE-----
EOM
GPGMeh.decrypt(encrypted_message) do |key_id|
  # This is the passphrase callback. The argument is Spiff's secret sub key id
  # that Rick used to encypt the message.
  # Return value: the secret keyring passphrase
  "spiff's-secret-keyring-passphrase"
end
```

### Symmetric Encryption: Rick wants to symmetrically encrypt and sign a message

```ruby
GPGMeh.encrypt_symmetric("boom") do |key_id|
  # This is the passphrase callback. The argument is Rick's secret key id OR :symmetric
  if key_id == :symmetric
    "the-symmetric-passphrase"
  else
    "rick's-secret-keyring-passphrase"
  end
end
```


### GPG setup (this was done to setup the tests, here for posterity)

Generate key for Rick Hardslab

```
gpg --homedir spec/support/rickhardslab --gen-key
```

Generate key for Spaceman Spiff

```
gpg --homedir spec/support/spacemanspiff --gen-key
```

Rick Hardslab imports Spaceman Spiff's public key

```
gpg --homedir rickhardslab --import spacemanspiff/pubring.gpg
```

Rick Hardslab trusts Spaceman Spiff's public key

```
gpg --homedir spec/support/spacemanspiff --export-ownertrust | gpg --homedir spec/support/rickhardslab --import-ownertrust
```

Spaceman Spiff imports Rick Hardslab's public key

```
gpg --homedir spacemanspiff --import rickhardslab/pubring.gpg
```

Spaceman Spiff trusts Rick Hardslab's public key

```
gpg --homedir spec/support/rickhardslab --export-ownertrust | gpg --homedir spec/support/spacemanspiff --import-ownertrust
```

Rick Hardslab's keys

```
% gpg --homedir rickhardslab -k
rickhardslab/pubring.gpg
------------------------
pub   2048R/243D6FEB 2016-01-18
uid                  Rick Hardslab <rick@example.com>
sub   2048R/7FCAE6B3 2016-01-18

pub   2048R/7CAAAB91 2016-01-18
uid                  Spaceman Spiff <spiff@example.com>
sub   2048R/11AB415A 2016-01-18

% gpg --homedir rickhardslab -K
rickhardslab/secring.gpg
------------------------
sec   2048R/243D6FEB 2016-01-18
uid                  Rick Hardslab <rick@example.com>
ssb   2048R/7FCAE6B3 2016-01-18
```

Spaceman Spiff's keys

```
% gpg --homedir spacemanspiff -K
spacemanspiff/secring.gpg
-------------------------
sec   2048R/7CAAAB91 2016-01-18
uid                  Spaceman Spiff <spiff@example.com>
ssb   2048R/11AB415A 2016-01-18

% gpg --homedir spacemanspiff -k
spacemanspiff/pubring.gpg
-------------------------
pub   2048R/7CAAAB91 2016-01-18
uid                  Spaceman Spiff <spiff@example.com>
sub   2048R/11AB415A 2016-01-18
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/gpgmeh.

