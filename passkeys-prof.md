# Passkeys Profile

(Some version of this text may be useful for the passkeys draft. This is 
very much a w-i-p as I read the specs and code... Don't believe anything
here very much for now.)

Conceptually, passkeys, (or webauthn) as used in IMAP or submission, is simple:

- a client-side (MUA-adjacent) authenticator has a per-service signature key
  pair
- the client-side authenticator can also ensure user prescence/consent, e.g.
  via a cryptographic key fob, or by having the authenticator bound to a mobile
  operating system
- and the client-side authenticator can produce an attestation about the above
  sufficient to convince a relying party (MS)

- a mail service's relying party (MS-adjacent) can carry out a registraiton
  ceremony, causing a client-side authenticator to generate a new key pair
  bound to the service, such that the relying party can bind the public key to a
  service account
- the relying party can subsequently authenticate a client/MUA based on a
  digital signature and challenge response

Note that the passkeys authentication stage is too onerous to be done
frequently, so just as session cookies are used on the web, we want a
form of bearer token, which is SASL remember me.

The various bits of passkeys specification are spread over a number of
documents and while the basic ideas are pretty obvious, (as shown above), the
details are often less clear (at least to this reader). So a summary of the
parts of those that may affect client and relying part implementations may be
useful:

There is an
[overview web page](https://fidoalliance.org/specifications-overview/)
and after that:

- [the webauthn spec](https://www.w3.org/TR/webauthn/) describes the
overall system, with a couple of nice overview diagrams
[here](https://www.w3.org/TR/webauthn/#sctn-api).

At registration time, the relying party gets to specify the following
[inputs](https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions) to the authenticator's create method:

- origin: a name for the relying party
- options: specifies the key generation parameters, specifically:
    - relying party: same as origin
    - user name: the account's email address
    - challenge: a random string
    - alg params:
        - type
        - ald id
    - timeout: seconds
    - excludecredentials: empty
    - authenticator details:
        - attachment: platform or cross-platform
        - residentkey: required/preferred/discouraged
        - requireresidentkey: false
        - userverification: required/preferred/discouraged
    - attestation: "none"
    - extensions: empty 
- sameOriginWithAncestors: a boolean that can be FALSE for all cases here
  (maybe;-)
