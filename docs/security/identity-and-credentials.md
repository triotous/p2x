# Identity and credentials

Product transport identities are persisted libp2p Ed25519 keypairs. Missing identities are fatal unless explicit onboarding enables creation. Secret files are bounded, regular files with no group/other permissions; private material is never emitted in diagnostics.

Clients and servers pin the exchange `PeerId` and validate every configured exchange address against that pin before authentication. A pin mismatch must close the connection without sending a credential.

Peer credentials use `p2x1.<credential-id>.<base64url-secret>`. The secret is 32 bytes of OS-generated entropy. The exchange stores only the domain-separated SHA-256 digest and binds it to peer, tenant, role, scopes, quota, and validity. Unknown IDs, wrong secrets, revoked credentials, expired credentials, and peer mismatches use the same public invalid-credential code.

Rotate by adding a second credential, deploying it, observing successful re-authentication, then revoking/removing the old credential at a higher authorization revision. Revocation invalidates new control work and sessions; it does not promise recall of already active direct streams.
