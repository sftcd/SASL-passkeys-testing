
# Setting up a test setup for SASL/passkeys

stephen.farrell@cs.tcd.ie, 2025-03-13
work-in-progress

As part of the work on
[SASL Remember Me](https://datatracker.ietf.org/doc/draft-ietf-kitten-sasl-rememberme/)
and [SASL Passkey](https://datatracker.ietf.org/doc/draft-bucksch-sasl-passkey/),
I wanted to setup a test environment that wouldn't interere with my daily-driver
desktop (Ubuntu 24.04), and that allows me to play with an old(ish) yubikey 4 nano
I had lying about, (firmware version 4.3.3), and some new solokeys and yubikey
5's I recently acquired, so the plan was/is:

- setup a guest VM also running Ubuntu 24.04 with graphics (DONE)
- figure out how to access the yubikey/solokey from the guest (DONE)
- do some basic tests to see if passkeys demos work there (DONE)
- setup a test mail setup on the guest (DONE)
- figure out how to integrate passkeys and rememberme into the mail test setup
- evolve that as the Internet-drafts mature

A goal is for this to be replicable so that others can re-use or come up with
variants. There seem to be many and varied ways in which passkeys/webauthn can
be used and I'm sure they'll have different wrinkles, so for this to be useful,
it'll need to be reusable by others. (Hence all the details:-)

## Guest VM creation:

I've used [`debvm`](https://manpages.ubuntu.com/manpages/noble/man1/debvm-create.1.html)
for setting up and running the guest VM. That ultimately runs [`qemu`](https://www.qemu.org/).

```bash
$ debvm-create --size=20G --release=noble --output ubuntu.ext4 -- --components=main,universe --include=e2fsprogs --hook-dir=/usr/share/mmdebstrap/hooks/useradd --aptopt='Apt::Install-Recommends "true"' --include=linux-image-generic,task-gnome-desktop
```

The 20GB disk is needed, I started with 10G but quickly hit 90% with this
setup.  Creating the VM takes maybe 5-10 minutes. You can also make the
disk bigger though if needed:

```bash
$ e2fsck -f 
$ resize2fs ubuntu.ext4 20G
resize2fs 1.47.0 (5-Feb-2023)
Resizing the filesystem on ubuntu.ext4 to 20971520 (1k) blocks.
The filesystem on ubuntu.ext4 is now 20971520 (1k) blocks long.
$ 
```

## Yubikey/Solokey on host

When I insert a yubikey/solokey, I need to pass on USB details to the guest OS
and to do that we need to know the bus and device/hostaddr, so, e.g.:

```bash
$ lsusb
...
Bus 001 Device 004: ID 1050:0407 Yubico.com Yubikey 4/5 OTP+U2F+CCID
...
```

I have to be careful where the mouse focus is when near the Yubikey 4 nano as
touching it, either in passing or when pulling it from the USB socket generates
some garbage looking text on (I guess) stdin - in one case that deleted a
message from my mail client:-) That doesn't seem to happen with the solokey.

Extracting the yubikey/solokey with this setup seems to require rebooting the
guest VM to allow it see the device again.

## Running the guest

I could have done more package installs and added an SSH public key during VM
creation but didn't. So I initially booted the VM then installed a bunch of the
usual dev packages, chromium-browser and an openssh-server via:

```bash
$ debvm-run -g -i ubuntu.ext4 -- -m 16G
```

That has a wrinkle - the mouse pointer is offset in the guest when the guest OS
window is displayed on my highish-res laptop screen, but works fine when I move
the window to a secondary screen connected via HDMI. After much mucking about,
it turns out adding the following seems to fix this:

```bash
    -vga none -device virtio-vga-gl -display sdl,gl=on 
```

After basic packages are installed and the SSH server is running I'm currently
starting the guest VM via, e.g.:

```bash
$ debvm-run -g -s 2222 -i ubuntu.ext4 -- -m 16G -usb -device usb-host,hostbus=1,hostaddr=4
```

The USB details above allow the guest to access the yubikey/solokey. Note that
those will change as you (dis/re)connect USB devices so you'd have to check
`lsusb` for the `Bus/hostbus` and `Device/hostaddr` before each boot. As those
values change, I wrote the [`bootvm.sh`](./bootvm.sh) script to grab 'em and
pass 'em on to the guest:

Then I can login as `user` via the graphics window, or SSH in via:

```bash
$ ssh -o NoHostAuthenticationForLocalhost=yes -p 2222  user@127.0.0.1
```

## Trying out passkeys in browsers

I next followed the instructions
[here](https://support.yubico.com/hc/en-us/articles/360016649039-Installing-Yubico-Software-on-Linux)
to install the required Yubikey s/w in the guest OS. I took the option to
download the `Yubikey authenticator` from the vendor's site rather than take
the distro's package.  (Since this is experimental stuff, maybe better to be
closer to bleeding edge.)

Next step was to try a passkeys [test site](https://webauthn.io/profile) in the
guest OS.  I registered (the site says it scrubs accounts after 24 hours), and
logged into a test account using chromium, which worked fine with the expected
"touch the device" interactions. I then confirmed that I could login to the
same account via firefox, again with the expected "touch the device"
interaction.  I also checked that authenticating via firefox after a guest
reboot worked too which is nice.

On a 2nd (old) laptop, also running Ubuntu 24.04, I tried to authenticate with
the same account (moving the Yubikey) and it also worked. On that machine,
before installing the Yubikey authenticator, I also had to add a new smartcard
handling package:

```bash
$ sudo apt install pcscd
```

So... so far so good!

With the yubikey 5 (firmware 5.7.1), the yubikey authenticator has a better
user inferface - you can see and manage the passkeys (up to 100 allowed on the
device I'm using). The yubikey 5 also seems to require a PIN before our
`mech_u2f.py` script will work. That can be set via the yubikey authenticator.
(And maybe also when accessing the passkey demo site, but didn't test that.)

## Solokeys in browser

As it's always better to not be dependent on one vendor, I acquired a few
[SoloKeys](https://solokeys.com) that also claim to be passkeys compatible.
Bottom line: turns out that's true, for our scenario, which is nice!

Solokeys are [open-source](https://github.com/solokeys) which is great, but the
repos don't seem to be active, which is less good. It could be that the
developers are focussing more on a "next gen" thing
(called [trussed](https://github.com/trussed-dev)) that's also intended to work with
[nitrokeys](https://www.nitrokey.com/), but "trussed" doesn't seem to have matured
just yet, hard to tell.

When I tried to use our python `mech_u2f.py register` before having set
a PIN I got an exception (trace [here](./solo-no-pin-except.md) in
case that's useful later).

The SoloKey device (or something;-) insisted on setting a PIN the first time I
tried it out via a browser (with the usual
[test site](https://webauthn.io/profile)).  After that, our `mech_u2f.py` script
works fine for registration and authentication with the device, prompting for
PIN entry and then to touch the authenticator.

There is a command line tool for SoloKeys, that first needs the
rust environment installed, then the tool itself. The online
documentation (that I found) wasn't quite correct but what worked
for me is below:

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
...
$ sudo apt install libusb-dev libudev-dev libpcsclite-dev
$ . $HOME/.cargo/env
$ cargo init
$ cargo install solo2
```

That all seems to work, though the `solo2` tool doesn't do so much
that's useful for my purposes, e.g. I've yet to find a way to unset
the PIN.

## DNS and PKI
 
I needed a DNS name for the guest VM so I used `pk.jell.ie` (`jell.ie` is a
vanity domain I control) and added that to `/etc/hosts` in the guest with
a localhost IP. I also needed a fake CA that mail and web clients can believe.

From another project I used a bash script
[`make-example-ca.sh`](https://github.com/defo-project/ech-dev-utils/blob/main/scripts/make-example-ca.sh)
that creates a fake CA and (wild-card) certificates for `example.com`.
Modifying that to replace `example.com` with `pk.jell.ie` is obvious enough and
once run I ended up with:

-  `$HOME/cadir/pk.jell.ie.pem` containing our wildcard cert
-  `$HOME/cadir/pk.jell.ie.priv` containing our private key
-  `$HOME/cadir/oe.csr` containing our fake CA public key 

As needed, I copied those certificate/key files into dovecot and nginx
configurations and installed the CA public key in firefox and thunderbird.

## Dovecot

I'll likely need a modified version of dovecot at some point so forked 
that, and since I'm used to it and it might be handy, I also did a local
build of openssl for the fun too, in the guest:

```bash
$ sudo apt install gettext bison flex libtool-bin pkgconf
$ cd $HOME/code
$ mkdir defo-project-org
$ cd defo-project-org
$ git clone https://github.com/defo-project/openssl
$ cd openssl
$ ./config --libdir=lib --prefix=$HOME/code/openssl-local-inst
$ make -j8
$ make install_sw
$ mdkir $HOME/code/dovecot
$ cd $HOME/code/dovecot
$ git clone https://github.com/sftcd/core.git
$ sudo apt install libpam0g-dev # needed for the --with-pam below
$ cd core
$ ./autogen.sh
$ export LD_LIBRARY_PATH=$HOME/code/openssl-local-inst/lib
$  EXTRA_CFLAGS=-O0 CPPFLAGS=-I$HOME/code/openssl-local-inst/include LDFLAGS=-L$HOME/code/openssl-local-inst/lib ./configure --enable-maintainer-mode --prefix=/usr/local/dovecot --with-pam
$ make -j8
```

The dovecot build is somewhat odd - it sometimes fails but then succeeds on a 2nd
attempt. Haven't investigated, but the error seems to be some test checking
online for something thing, so we'll see.

Also worth noting are some
[debugging tips](https://doc.dovecot.org/2.3/developer_manual/development_tips/debugging_tips/).

## A simplified postfix/dovecot/thunderbird setup

Next I installed a simple postfix/dovecot setup on the guest with postfix,
dovecot-imapd, dovecot-lmtpd and thunderbird.  Getting that all working in the
guest was finickkity, but copying from other setups eventually worked.  That
setup can send mail externally or to itself, and thunderbird can do IMAP
operations, so I should be able to play with SASL autentication for submission
and IMAP operations.

The postfix `main.cf` config things I changed are below
(I think;-):

```bash
mydestination = pk.jell.ie, $myhostname, localhost, localhost.localdomain, localhost
myhostname = pk.jell.ie
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
smtpd_sasl_type = dovecot
smtpd_tls_cert_file = /etc/dovecot/private/pk.jell.ie.pem
smtpd_tls_key_file = /etc/dovecot/private/pk.jell.ie.priv
virtual_transport = lmtp:unix:private/dovecot-lmtp
```

And (I think, again;-) the only change in `master.cf` was the addition of:

```bash
submission inet  n       -       -       -       -       smtpd
    -o syslog_name=postfix/submission -o smtpd_tls_security_level=encrypt
    -o smtpd_sasl_auth_enable=yes -o smtpd_sasl_type=dovecot
    -o smtpd_sasl_path=private/auth -o smtpd_sasl_security_options=noanonymous
    -o smtpd_sasl_local_domain= -o smtpd_client_restrictions=permit_sasl_authenticated,reject
    -o smtpd_recipient_restrictions=reject_non_fqdn_recipient,reject_unknown_recipient_domain,permit_sasl_authenticated,reject
    -o smtpd_relay_restrictions=permit_sasl_authenticated,rejec
```

## Installing the local dovecot build 

It's not sure if first using the disto's version of dovecot is a good plan, but
that's what I did:-) Next was to replace that with the locally built dovecot.
The bleeding-edge config files were a little different from the distros.

```bash
$ cd $HOME/code/dovecot/core
$ sudo make install
...
```

Each time one does that you zap some files that systemd needs to run the
distro's dovecot so going back and forth seems to be non-trivial, but hopefully
I won't need to.

My dovecot config is then:

```bash
$ dovecot/sbin/dovecot -n
# 0.0.0-35009+61e3708fb5 (b153621271): /usr/local/dovecot/etc/dovecot/dovecot.conf
# OS: Linux 6.8.0-55-generic x86_64 Ubuntu 24.04.2 LTS 
# Hostname: localhost
# 4 default setting changes since version 0.0.0
dovecot_config_version = 0.0.0
dovecot_storage_version = 2.3.0
mail_driver = sdbox
mail_gid = mail
mail_path = ~/mail
mail_uid = mail
protocols = imap lmtp
recipient_delimiter = +_
ssl = required
service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}
service lmtp {
  user = mail
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    group = postfix
    mode = 0600
    user = postfix
  }
}
protocol lmtp {
  postmaster_address = user@pk.jell.ie
}
dict dict {
}
passdb pdb {
  driver = pam
}
userdb udb {
  driver = passwd
}
ssl_server {
  cert_file = /etc/dovecot/private/pk.jell.ie.pem
  key_file = /etc/dovecot/private/pk.jell.ie.priv
}
```

Note that the dovecot upstream seems to change fairly rapidly, e.g. the 
name of the config entries for the TLS files changed between the first
and second commits to this repo. I figured out the new names by moving
`/usr/local/dovevot` aside, then doing another `make install` with 
the latest upstream, which allowed me to see what was now expected to
be in `/usr/local/dovecot/etc/dovecot/dovecot.conf`. Not sure if
doing that'll be a common thing or exceptional.

With the above setup, mail content is stored in `$HOME/mail/mailboxes/`
in I'm not sure what format - not mbox or Maildir anyway, presumably
something more modern.

## A PoC dovecot passkeys mechanism

Aki Tuomi (impressively quickly) did up a
[PoC implementation](https://github.com/cmouse/dovecot-mech-passkey/)
of the passkeys authentication method for dovecot, so trying that
made sense.

## Python client test

I can use a bit of python in Aki's repo as a test, the
example below uses a solokey (with a PIN) rather than the
yubikey (without a PIN) but both work:

```bash
$ python mech_u2f.py register
DEBUG:PASSKEYAuthenticator:Use USB HID channel.
CtapHidDevice('/dev/hidraw0')
DEBUG:PASSKEYAuthenticator:Use USB HID channel.
CtapHidDevice('/dev/hidraw0')
DEBUG:fido2.server:Fido2Server initialized for RP: PublicKeyCredentialRpEntity(name='Example RP', id='imap.example.com')
DEBUG:fido2.server:Starting new registration, existing credentials: 
DEBUG:fido2.client:Register a new credential for RP ID: imap.example.com
Enter PIN: 
DEBUG:fido2.ctap2.pin:Got PIN token for permissions: None
DEBUG:fido2.ctap2.base:Calling CTAP2 make_credential
DEBUG:fido2.hid:Got keepalive status: 01
DEBUG:fido2.hid:Got keepalive status: 02

Touch your authenticator device now...

DEBUG:fido2.hid:Got keepalive status: 01
DEBUG:fido2.hid:Got keepalive status: 01
DEBUG:fido2.hid:Got keepalive status: 01
DEBUG:fido2.hid:Got keepalive status: 01
DEBUG:fido2.hid:Got keepalive status: 01
DEBUG:fido2.server:Verifying attestation of type packed
INFO:fido2.server:New credential registered: a300589ee0f0b3c58410d3c4058a4589171f5564949ea5d6693452d67142f01315cdaea3f18381ccbbafcf20c23aa29d866b061509aba7d16937b1bff3a3561a4f1f6f21847edfeeb9e987aaab8dc04559b4ba3c22fe644d52a276fa28ae328de3447b8ddfea942e9487e168dc2f70d121a5ca2dc9d8dd5d4a3d0d9534d9f9aedefd36c1e7683fef4ba8e5818c55bbcab87439dfa916339ff67c8d4b99252a4f8a79014cf37608acbb9b1d0cd19c4fb902502f75ea123e6f1c7c026c833275f1bad4
{PASSKEY}i8VJaAexTV+ySWB/XVJ9ogDCowBYnuDws8WEENPEBYpFiRcfVWSUnqXWaTRS1nFC8BMVza6j8YOBzLuvzyDCOqKdhmsGFQmrp9FpN7G/86NWGk8fbyGEft/uuemHqquNwEVZtLo8Iv5kTVKidvoorjKN40R7jd/qlC6Uh+Fo3C9w0SGlyi3J2N1dSj0NlTTZ+a7e/TbB52g/70uo5YGMVbvKuHQ536kWM5/2fI1LmSUqT4p5AUzzdgisu5sdDNGcT7kCUC916hI+bxx8AmyDMnXxutSkAQEDJyAGIVggI7w2IZUEQDsDFSVvlro1HazmOkc7YFV3HQtrzWf07W8=
user@pk:~/code/dovecot/dovecot-mech-passkey$ python mech_u2f.py auth {PASSKEY}i8VJaAexTV+ySWB/XVJ9ogDCowBYnuDws8WEENPEBYpFiRcfVWSUnqXWaTRS1nFC8BMVza6j8YOBzLuvzyDCOqKdhmsGFQmrp9FpN7G/86NWGk8fbyGEft/uuemHqquNwEVZtLo8Iv5kTVKidvoorjKN40R7jd/qlC6Uh+Fo3C9w0SGlyi3J2N1dSj0NlTTZ+a7e/TbB52g/70uo5YGMVbvKuHQ536kWM5/2fI1LmSUqT4p5AUzzdgisu5sdDNGcT7kCUC916hI+bxx8AmyDMnXxutSkAQEDJyAGIVggI7w2IZUEQDsDFSVvlro1HazmOkc7YFV3HQtrzWf07W8=
CtapHidDevice('/dev/hidraw0')
Enter PIN: 

Touch your authenticator device now...

Authentication finished

```

The registration output (`{PASSKEY}...`) can be saved as a credential
and used in a test with the PoC code.

## Building the PoC

```bash
$ sudo apt install libfido2-dev libcbor-dev
$ cd $HOME/code/dovecot
$ git clone https://github.com/cmouse/dovecot-mech-passkey/
$ cd dovecot-mech-passkey
$ ./autogen.sh
$ ./configure  --with-dovecot=../core
$ make -j12
...currently some warnings but builds...
```

Then we can pass in the credential produced by `mech_u2f.py` and see
how that goes. Currently, it looks ok for the yubikey but we get an
error for the solokey that looks like an algorithm mis-match maybe.

```
$ ./src/test ~/cred-yubi4 
Debug: got guid 00000000-0000-0000-0000-000000000000
Debug: cred size = 64, size = 143
Debug: Got credential id 33a280212144cdeef03fca17892f5f7f5a5a87e8be9478220a3b7b748bd654d23473ff671db8549c77b45ec552a8636bc6d11ec77ae397911878d005830125be
Debug: item is 5
Debug: key is 1
Debug: Key type = 2
Debug: item is 5
Debug: key is 3
Debug: algorithm = -7
Debug: item is 5
Debug: key is -1
Debug: curve = 1
Debug: item is 5
Debug: key is -2
Debug: x = 32 bytes
Debug: item is 5
Debug: key is -3
Debug: y = 32 bytes
Debug: R: a564727049646b6578616d706c652e636f6d696368616c6c656e676558203fd8753eb1003843287ee8ef84646982a2e07e8bf248c6850e8830caae8702796774696d656f75741b000000000000ea6070616c6c6f7743726564656e7469616c7381a2626964584033a280212144cdeef03fca17892f5f7f5a5a87e8be9478220a3b7b748bd654d23473ff671db8549c77b45ec552a8636bc6d11ec77ae397911878d005830125be64747970656a7075626c69632d6b65797075736572566572696669636174696f6e687265717569726564
mech passkey ......................................................... : ok
0 / 1 tests failed
$ ./src/test ~/cred-solo 
Debug: got guid 8bc54968-07b1-4d5f-b249-607f5d527da2
Debug: cred size = 194, size = 238
Debug: Got credential id a300589e0585c5e1d938355fb006ae2feacd37832493b6950f0aaed6d57719496a477b528b2b2c9be38ae743c6933223ca7fec4b276ed8ab6482d242cfa3edaac1f1304723997442d7a75fef01f9dd0054b62e4187df4c98ea0f92d2882d935ee12fa106c3e33b33dcbac8df0b48216bfb35e487a4a761bdcedbd2eac68801d0193ad78e261067fd40e37783cf6fdb0d6733fa879303aadb683ed1f2dbb263c19ec5014c7fadcc4a74eb4eb47a15cc9f0250e5a1c986e1c5f4376b5432a7631b5418
Debug: item is 5
Debug: key is 1
Debug: Key type = 1
Debug: item is 5
Debug: key is 3
Debug: algorithm = -8
Debug: item is 5
Debug: key is -1
Debug: curve = 6
Debug: item is 5
Debug: key is -2
Debug: x = 32 bytes
Debug: error:08000066:elliptic curve routines::invalid encoding
Debug: R: 
mech passkey ......................................................... : ok
0 / 1 tests failed
```

The yubikey 5 seems to use the same algorithms as the yubikey 4 as
shown above. 

It looks like the `algorithm` is the difference here - `-7` is the
[CBOR code point](https://www.iana.org/assignments/cose/cose.xhtml)
for ES256 (or ECDSA with SHA-256), and `1` means NIST P256 for the curve,
whereas `-8` is the CBOR code point for EdDSA, with `6` meaning ed25519 for the
curve, so I guess the solokeys is using the latter and that's either not
supported or configured in our dovecot build.

I don't see a way to change algorithm/curve preferences (so far) with either
yubikeys or solokeys.

## A local passkeys registration site/relying party 

I'll want some more complex registration scheme so will need a web server
that does that. 

To start I need an nginx and to make that work with a (guest VM) browser for
https, based on my DNS/PKI setup, that means uncommenting the port 443 server
lines and adding the `pk.jell.ie` cert and private key ending up with the
following lines in the `server` stanzas of `/etc/nginx/sites-enabled/default`:

```bash
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        ssl_certificate /etc/nginx/pk.jell.ie.pem;
        ssl_certificate_key /etc/nginx/pk.jell.ie.priv;
```

I've yet to get a passkeys reg/auth setup working with that nginx instance.

## State of play

And that's where I'm at (as of 2025-03-13). Things to do in future are:

- get the local nginx setup working for passkeys registration/auth
- probably get some simple command line demo of the passkeys auth with dovecot
- hack thunderbird to do the same (or some of it, or choose an easier IMAP
  capable MUA, maybe)


