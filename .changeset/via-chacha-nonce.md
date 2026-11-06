---
"ssh-mcp": patch
---

A `via` (ProxyJump) profile now connects when both hops are OpenSSH and ssh2's optional native crypto binding is absent. That covers the published Docker image and installs that could not build the binding. Before, the inner handshake hung after its first encrypted packet and then failed with "SSH connection ended during handshake" (#315).

The cause is in ssh2 (mscdex/ssh2#1523). Its JavaScript chacha20-poly1305 cipher corrupts the nonce when one connection is carried inside another that also uses chacha20. Connections over a bastion now offer chacha20-poly1305 last, so any other cipher both sides support is chosen first.

A server behind a bastion that accepts only chacha20-poly1305 is still offered it. Without the native binding it still hangs, as it did before this change. Nothing that connected before stops connecting.
