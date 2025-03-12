
# Setting up a test setup for SASL/passkeys

stephen.farrell@cs.tcd.ie, 2025-03-12
work-in-progress

As part of the work on
[SASL Remember Me](https://datatracker.ietf.org/doc/draft-ietf-kitten-sasl-rememberme/)
and [SASL Passkey](https://datatracker.ietf.org/doc/draft-bucksch-sasl-passkey/),
I wanted to setup a test environment that wouldn't interere with my daily-driver
desktop (Ubuntu 24.04), and that allows me to play with an old(ish) Yubikey 4 nano
I had lying about, (firmware version 4.3.3), so the plan was/is:

- setup a guest VM also running Ubuntu 24.04 with graphics (DONE)
- figure out how to access the yubikey from the guest (DONE)
- do some basic tests to see if passkeys demos work there (DONE)
- setup a test mail setup on the guest (DONE)
- figure out how to integrate passkeys and rememberme into the mail test setup
- evolve that as the Internet-drafts mature

A goal is for this to be replicable so that others can re-use or come up with
variants. There seem to be many and varied ways in which passkeys/webauthn can
be used and I'm sure they'll have different wrinkles, so for this to be useful,
it'll need to be reusable by others. (Hence all the details:-)

I've used [`debvm`](https://manpages.ubuntu.com/manpages/noble/man1/debvm-create.1.html)
for setting up and running the guest VM. That ultimately runs [`qemu`](https://www.qemu.org/).

## Guest VM creation:

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

## Yubikey on host

When I insert the yubikey, I need to pass on USB details to the guest OS and
to do that we need to know the bus and device/hostaddr, so:

```bash
$ lsusb
...
Bus 001 Device 004: ID 1050:0407 Yubico.com Yubikey 4/5 OTP+U2F+CCID
...
```

I have to be careful where the mouse focus is when near the Yubikey 4 nano as
touching it, either in passing or when pulling it from the USB socket generates
some garbage looking text on (I guess) stdin - in one case that deleted a
message from my mail client:-)

Extracting the yubikey with this setup seems to require rebooting the guest VM
to see the device again.

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
starting the guest VM via:

```bash
$ debvm-run -g -s 2222 -i ubuntu.ext4 -- -m 16G -usb -device usb-host,hostbus=1,hostaddr=4
```

The USB details above allow the guest to access the Yubikey. Note that those
will change as you (dis/re)connect USB devices so you probably have to check
`lsusb` for the `Bus/hostbus` and `Device/hostaddr` before each boot. As those
values change, I wrote a script to grab 'em and pass 'em on to the guest:

```bash
#!/bin/bash

# set -x

function stripleadingzeros()
{
    echo $((10#$1))
}

HBUS=$(stripleadingzeros `lsusb | grep Yubico | awk '{print $2}'`)
HADDR=$(stripleadingzeros `lsusb | grep Yubico | awk '{print $4}' | sed -e 's/://'`)

debvm-run -g -s 2222 -i ubuntu.ext4 -- -m 16G \
    -usb -device usb-host,hostbus=$HBUS,hostaddr=$HADDR \
    -vga none -device virtio-vga-gl -display sdl,gl=on
```

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

## DNS and PKI
 
I needed a DNS name for the guest VM so I used `pk.jell.ie` (`jell.ie` is a
vanity domain I do control) and added that to `/etc/hosts` in the guest with
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

The build is somewhat odd - it sometimes fails but then succeeds on a 2nd
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
$ /usr/local/dovecot/sbin/dovecot -n
$ sudo ./sbin/dovecot -n
# 0.0.0-33418+f9bda94b25 (f9bda94b25): /usr/local/dovecot/etc/dovecot/dovecot.conf
# OS: Linux 6.8.0-54-generic x86_64 Ubuntu 24.04.2 LTS 
# Hostname: localhost
dovecot_config_version = 0.0.0
dovecot_storage_version = 2.3.0
mail_gid = mail
mail_location = mbox:~/mail:INBOX=/var/mail/%u
mail_uid = mail
protocols = imap lmtp
recipient_delimiter = +_
ssl = required
ssl_cert = </etc/dovecot/private/pk.jell.ie.pem
ssl_key = # hidden, use -P to show it
service auth {
  name = auth
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    path = /var/spool/postfix/private/auth
    user = postfix
  }
}
service lmtp {
  name = lmtp
  user = mail
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    group = postfix
    mode = 0600
    path = /var/spool/postfix/private/dovecot-lmtp
    user = postfix
  }
}
protocol lmtp {
  postmaster_address = user@pk.jell.ie
}
passdb pdb {
  driver = pam
  name = pdb
}
userdb udb {
  driver = passwd
  name = udb
}
```

## A PoC dovecot passkeys mechanism

Aki Tuomi (impressively quickly) did up a
[PoC implementation](https://github.com/cmouse/dovecot-mech-passkey/)
of the passkeys authentication method for dovecot, so trying that
made sense.

```bash
$ sudo apt install libfido2-dev libcbor-dev
$ cd $HOME/code/dovecot
$ git clone https://github.com/cmouse/dovecot-mech-passkey/
$ cd dovecot-mech-passkey
$ ./autogen.sh
$ ./configure  --with-dovecot=../core
$ make -j12
...currently some errors, hopefully to be fixed next day or so...
```

I can now use a bit of python in that repo as a test:

```bash
$ python mech_u2f.py register
DEBUG:PASSKEYAuthenticator:Use USB HID channel.
CtapHidDevice('/dev/hidraw1')
DEBUG:PASSKEYAuthenticator:Use USB HID channel.
CtapHidDevice('/dev/hidraw1')
DEBUG:fido2.server:Fido2Server initialized for RP: PublicKeyCredentialRpEntity(name='Example RP', id='imap.example.com')
DEBUG:fido2.server:Starting new registration, existing credentials: 
DEBUG:fido2.client:Register a new credential for RP ID: imap.example.com

Touch your authenticator device now...

DEBUG:fido2.server:Verifying attestation of type fido-u2f
INFO:fido2.server:New credential registered: d488a7bad3587265c5076027cb77ac2cf5e5162506340df5bb2ce31de5b015a2361a9e4e4e6d2c0ec16a20748cce0871c9abe47400947abdccc812085dc4c1cf
{PASSKEY}AAAAAAAAAAAAAAAAAAAAAABA1IinutNYcmXFB2Any3esLPXlFiUGNA31uyzjHeWwFaI2Gp5OTm0sDsFqIHSMzghxyavkdACUer3MyBIIXcTBz6UBAgMmIAEhWCBJIZpSV9VBohhaqMkwH35econ1OVWOOE48vjnENI812yJYIG9gsNveRcXq86xzNayOFUgNRVVqNRgK592ts0PR+BB+
$ 
$ 
$ python mech_u2f.py auth {PASSKEY}AAAAAAAAAAAAAAAAAAAAAABA1IinutNYcmXFB2Any3esLPXlFiUGNA31uyzjHeWwFaI2Gp5OTm0sDsFqIHSMzghxyavkdACUer3MyBIIXcTBz6UBAgMmIAEhWCBJIZpSV9VBohhaqMkwH35econ1OVWOOE48vjnENI812yJYIG9gsNveRcXq86xzNayOFUgNRVVqNRgK592ts0PR+BB+
DEBUG:PASSKEYAuthenticator:Use USB HID channel.
CtapHidDevice('/dev/hidraw1')
DEBUG:fido2.server:Fido2Server initialized for RP: PublicKeyCredentialRpEntity(name='Example RP', id='imap.example.com')
DEBUG:fido2.server:Starting new authentication, for credentials: d488a7bad3587265c5076027cb77ac2cf5e5162506340df5bb2ce31de5b015a2361a9e4e4e6d2c0ec16a20748cce0871c9abe47400947abdccc812085dc4c1cf
DEBUG:fido2.client:Assert a credential for RP ID: imap.example.com

Touch your authenticator device now...

INFO:fido2.server:Credential authenticated: d488a7bad3587265c5076027cb77ac2cf5e5162506340df5bb2ce31de5b015a2361a9e4e4e6d2c0ec16a20748cce0871c9abe47400947abdccc812085dc4c1cf
```

That needed a few minor edits from the repo's `mech_u2f.py` to work in my
setup, the diff is:

```bash

diff --git a/mech_u2f.py b/mech_u2f.py
index ab49e9a..543a419 100644
--- a/mech_u2f.py
+++ b/mech_u2f.py
@@ -99,7 +99,7 @@ def authn(data):
         logging.error("Credential does not start with {PASSKEY}")
         sys.exit(1)

-    mech = PASSKEYAuthenticator("user_id", appid="https://example.com")
+    mech = PASSKEYAuthenticator("user_id", appid="https://imap.example.com")

     user = mech("")

@@ -107,12 +107,14 @@ def authn(data):

     credential, _ = AttestedCredentialData.unpack_from(b64decode(data[9:]))
     uv = "preferred"
-    server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")
+    server = Fido2Server({"id": "imap.example.com", "name": "Example RP"}, attestation="direct")
     request_options, state = server.authenticate_begin([credential], user_verification=uv)

     result = cbor.decode(mech(cbor.encode(request_options.public_key)))
+    # result = AuthenticatorAssertionResponse(client_data=result['clientDataJSON'], authenticator_data=result['authenticatorData'],
+            # signature = result['signature'], credential_id=result['credentialId'], extension_results=result['extensionResults'])
     result = AuthenticatorAssertionResponse(client_data=result['clientDataJSON'], authenticator_data=result['authenticatorData'],
-            signature = result['signature'], credential_id=result['credentialId'], extension_results=result['extensionResults'])
+            signature = result['signature'], credential_id=result['credentialId'])


     server.authenticate_complete(
@@ -144,6 +146,7 @@ def reg():


 def main():
+    logging.basicConfig(level=logging.DEBUG)
     if len(sys.argv) < 2:
         print("Usage: test.py auth <credential>|register")
     elif sys.argv[1] == "auth" and len(sys.argv) > 2:
```

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

And that's where I'm at (as of 2025-03-12). Things to do in future are:

- rebase dovecot once the passkeys PoC is upstreamed some version of that
- get the local nginx setup working for passkeys registration/auth
- probably get some simple command line demo of the passkeys auth with dovecot
- hack thunderbird to do the same (or some of it, or choose an easier IMAP
  capable MUA, maybe)


