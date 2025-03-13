
# Exception when trying to register a SoloKey before having set a PIN

When I tried to use our python `mech_u2f.py register` before having set
a PIN I got the exception below.

The [SoloKey](https://solokeys.eu/) device (or something) insisted on setting a
PIN the first time I tried it out via a browser (with the usual
[test site](https://webauthn.io/profile)).  After that our `mech_u2f.py` script
works fine for registration and authentication with the device, prompting for
PIN entry and then to touch the authenticator.

```
$ python mech_u2f.py register
DEBUG:PASSKEYAuthenticator:Use USB HID channel.
CtapHidDevice('/dev/hidraw0')
DEBUG:PASSKEYAuthenticator:Use USB HID channel.
CtapHidDevice('/dev/hidraw0')
DEBUG:fido2.server:Fido2Server initialized for RP: PublicKeyCredentialRpEntity(name='Example RP', id='imap.example.com')
DEBUG:fido2.server:Starting new registration, existing credentials: 
DEBUG:fido2.client:Register a new credential for RP ID: imap.example.com
Traceback (most recent call last):
  File "/home/user/code/dovecot/dovecot-mech-passkey/mech_u2f.py", line 161, in <module>
    main()
  File "/home/user/code/dovecot/dovecot-mech-passkey/mech_u2f.py", line 155, in main
    reg()
  File "/home/user/code/dovecot/dovecot-mech-passkey/mech_u2f.py", line 138, in reg
    result = client.make_credential(create_options["publicKey"])
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/fido2/client.py", line 797, in make_credential
    return self._backend.do_make_credential(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/fido2/client.py", line 598, in do_make_credential
    pin_protocol, pin_token, pin_auth, internal_uv = self._get_auth_params(
                                                     ^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/fido2/client.py", line 536, in _get_auth_params
    if self._should_use_uv(user_verification, mc) or permissions:
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/fido2/client.py", line 492, in _should_use_uv
    raise ClientError.ERR.CONFIGURATION_UNSUPPORTED(
fido2.client.ClientError: (<ERR.CONFIGURATION_UNSUPPORTED: 3>, 'User verification not configured/supported')
$ 
```
