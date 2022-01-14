# XXXDH_JS
WASM wrapper around xxxdh library implementing Extended Triple Diffie-Hellman key exchange.

## Usage
```javascript
import * as xxxdh from "xxxdh-js";

let alice_identity = new xxxdh.X25519RistrettoKeyPair();
let alice_prekey = new xxxdh.X25519RistrettoKeyPair();
let alice_signature = alice_identity.sign(alice_prekey.public);
let alice_protocol = new xxxdh.ProtocolX25519RistrettoInMemSha256Aes256Gm(alice_identity.to_vec(), alice_prekey.to_vec(), alice_signature);

let onetime_keypair = new xxxdh.X25519RistrettoKeyPair();

let bob_identity = new xxxdh.X25519RistrettoKeyPair();
let bob_prekey = new xxxdh.X25519RistrettoKeyPair();
let bob_signature = bob_identity.sign(bob_prekey.public);
let bob_protocol = new xxxdh.ProtocolX25519RistrettoInMemSha256Aes256Gm(bob_identity.to_vec(), bob_prekey.to_vec(), bob_signature, [onetime_keypair.to_vec()]);

let alice_msg = alice_protocol.prepare_init_msg(bob_identity.public, bob_prekey.public, bob_signature, onetime_keypair.public);
let alice_init_msg = alice_msg.init_msg;
let alice_sk = alice_msg.shared_secret;

let bob_sk = bob_protocol.derive_shared_secret(
    alice_init_msg.sender_identity,
    alice_init_msg.sender_ephemerial_key,
    alice_init_msg.receiver_onetime_key,
    alice_init_msg.nonce, alice_init_msg.cyphertext
);

console.log("Alice:", alice_sk);
console.log("Bob:", bob_sk);
```