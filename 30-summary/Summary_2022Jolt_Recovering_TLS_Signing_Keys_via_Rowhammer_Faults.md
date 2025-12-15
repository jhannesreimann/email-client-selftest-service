# Is it a good match for us?

No.

1) not enough "networking" in it
* rowhammer needs co-location of server and client (to share DRAM) and that's what they do in the paper

* there are other papers that talk about Rowhammer in cloud environments but it's difficult for us not only to implement Jolt by ourselves but also extend it.


2) no open-source Jolt implementation
* code for the Jolt attack is not published and I couldn't find any implementation. So it seems just unnecessarily difficult

3) DRAM chip is necessary

# Summary

## Background:

* "Digital Signature Schemes such as DSA, ECDSA, and RSA are widely deployed to protect the integrity of security protocols such as TLS, SSH, and IPSec. In TLS, for instance, RSA and (EC)DSA are used to sign the state of the agreed upon protocol parameters during the handshake phase."

## Jolt
* Jolt attack "exploits faulty signatures gained by injecting faults during signature generation"

* the technique works by
1) co-locating with the victim and injecting faults into the victim memory space with Rowhammer.

2) post-process the faulty signatures using Jolt, an ElGamal style-specific SCA, which yields the signing key. The attack applies to ElGamal style signature schemes such as (EC)DSA, Schnorr and RSA signatures

* authors find that TLS 1.2 and 1.3 implementations in OpenSSL, WolfSSL, LibreSSL, Microsoft
SymCrypt, Amazon s2n are vulnerable.
Most of them were patched, but OpenSSL and Microsoft Symcrypt "opted against issuing patches" as "Rowhammer is currently not in their threat model".

* attack is demonstrated on TLS
