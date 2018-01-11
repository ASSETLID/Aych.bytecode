type generichash_state

class type keypair = object
  method publicKey : Typed_array.uint8Array Js.t Js.prop
  method privateKey : Typed_array.uint8Array Js.t Js.prop
end

class type sodium = object

  method from_string_ : Js.js_string Js.t -> Typed_array.uint8Array Js.t Js.meth
  method to_hex_ : Typed_array.uint8Array Js.t -> Js.js_string Js.t Js.meth
  method compare : 'a -> 'a -> int Js.meth
  method memcmp :
    Typed_array.uint8Array Js.t -> Typed_array.uint8Array Js.t -> bool Js.meth
  method memzero : Typed_array.uint8Array Js.t -> unit Js.meth

  (* Generic hash *)
  method crypto_generichash_BYTES_ : int Js.prop
  method crypto_generichash_BYTES_MIN_ : int Js.prop
  method crypto_generichash_BYTES_MAX_ : int Js.prop
  method crypto_generichash_KEYBYTES_ : int Js.prop
  method crypto_generichash_KEYBYTES_MIN_ : int Js.prop
  method crypto_generichash_KEYBYTES_MAX_ : int Js.prop
  method crypto_generichash_ :
    int -> Typed_array.uint8Array Js.t -> Typed_array.uint8Array Js.t ->
    Typed_array.uint8Array Js.t Js.meth
  method crypto_generichash_keygen_ :
    unit -> Typed_array.uint8Array Js.t Js.meth
  method crypto_generichash_init_ :
    Typed_array.uint8Array Js.t -> int -> generichash_state Js.meth
  method crypto_generichash_update_ :
    generichash_state -> Typed_array.uint8Array Js.t -> unit Js.meth
  method crypto_generichash_final_ :
    generichash_state -> int -> Typed_array.uint8Array Js.t Js.meth

  (* Sign *)
  method crypto_sign_BYTES_ : int Js.prop
  method crypto_sign_PUBLICKEYBYTES_ : int Js.prop
  method crypto_sign_SECRETKEYBYTES_ : int Js.prop
  method crypto_sign_SEEDBYTES_ : int Js.prop
  method crypto_sign_keypair_ : unit -> keypair Js.t Js.meth
  method crypto_sign_seed_keypair_ :
    Typed_array.uint8Array Js.t -> keypair Js.t Js.meth
  method crypto_sign_ :
    Typed_array.uint8Array Js.t -> Typed_array.uint8Array Js.t ->
    Typed_array.uint8Array Js.t Js.meth
  method crypto_sign_open_ :
    Typed_array.uint8Array Js.t -> Typed_array.uint8Array Js.t ->
    Typed_array.uint8Array Js.t Js.meth
  method crypto_sign_detached_ :
    Typed_array.uint8Array Js.t -> Typed_array.uint8Array Js.t ->
    Typed_array.uint8Array Js.t Js.meth
  method crypto_sign_verify_detached_ :
    Typed_array.uint8Array Js.t -> Typed_array.uint8Array Js.t ->
    Typed_array.uint8Array Js.t -> bool Js.meth
  method crypto_sign_ed25519_sk_to_pk_ :
    Typed_array.uint8Array Js.t -> Typed_array.uint8Array Js.t Js.meth
  method crypto_sign_ed25519_sk_to_seed_ :
    Typed_array.uint8Array Js.t -> Typed_array.uint8Array Js.t Js.meth

end

(*

SODIUM_LIBRARY_VERSION_MAJOR : 10
SODIUM_LIBRARY_VERSION_MINOR : 1
SODIUM_VERSION_STRING : "1.0.16"
add : ƒ (A,e)
base64_variants : {ORIGINAL: 1, ORIGINAL_NO_PADDING: 3, URLSAFE: 5, URLSAFE_NO_PADDING: 7}
compare : ƒ (A,e)
crypto_aead_chacha20poly1305_ABYTES : 16
crypto_aead_chacha20poly1305_KEYBYTES : 32
crypto_aead_chacha20poly1305_NPUBBYTES : 8
crypto_aead_chacha20poly1305_NSECBYTES : 0
crypto_aead_chacha20poly1305_decrypt : ƒ l(A,e,a,t,I,r)
crypto_aead_chacha20poly1305_decrypt_detached : ƒ f(A,e,a,t,I,r,g)
crypto_aead_chacha20poly1305_encrypt : ƒ u(A,e,a,t,I,r)
crypto_aead_chacha20poly1305_encrypt_detached : ƒ w(A,e,a,t,I,r)
crypto_aead_chacha20poly1305_ietf_ABYTES : 16
crypto_aead_chacha20poly1305_ietf_KEYBYTES : 32
crypto_aead_chacha20poly1305_ietf_NPUBBYTES : 12
crypto_aead_chacha20poly1305_ietf_NSECBYTES : 0
crypto_aead_chacha20poly1305_ietf_decrypt : ƒ b(A,e,a,t,I,r)
crypto_aead_chacha20poly1305_ietf_decrypt_detached : ƒ d(A,e,a,t,I,r,g)
crypto_aead_chacha20poly1305_ietf_encrypt : ƒ D(A,e,a,t,I,r)
crypto_aead_chacha20poly1305_ietf_encrypt_detached : ƒ m(A,e,a,t,I,r)
crypto_aead_chacha20poly1305_ietf_keygen : ƒ k(A)
crypto_aead_chacha20poly1305_keygen : ƒ F(A)
crypto_aead_xchacha20poly1305_ietf_ABYTES : 16
crypto_aead_xchacha20poly1305_ietf_KEYBYTES : 32
crypto_aead_xchacha20poly1305_ietf_NPUBBYTES : 24
crypto_aead_xchacha20poly1305_ietf_NSECBYTES : 0
crypto_aead_xchacha20poly1305_ietf_decrypt : ƒ v(A,e,a,t,I,r)
crypto_aead_xchacha20poly1305_ietf_decrypt_detached : ƒ M(A,e,a,t,I,r,g)
crypto_aead_xchacha20poly1305_ietf_encrypt : ƒ G(A,e,a,t,I,r)
crypto_aead_xchacha20poly1305_ietf_encrypt_detached : ƒ N(A,e,a,t,I,r)
crypto_aead_xchacha20poly1305_ietf_keygen : ƒ Y(A)
crypto_auth : ƒ H(A,e,a)
crypto_auth_BYTES : 32
crypto_auth_KEYBYTES : 32
crypto_auth_hmacsha256 : ƒ x(A,e,a)
crypto_auth_hmacsha256_BYTES : 32
crypto_auth_hmacsha256_KEYBYTES : 32
crypto_auth_hmacsha256_keygen : ƒ S(A)
crypto_auth_hmacsha256_verify : ƒ R(A,e,a)
crypto_auth_hmacsha512 : ƒ J(A,e,a)
crypto_auth_hmacsha512_BYTES : 64
crypto_auth_hmacsha512_KEYBYTES : 32
crypto_auth_hmacsha512_keygen : ƒ X(A)
crypto_auth_hmacsha512_verify : ƒ U(A,e,a)
crypto_auth_keygen : ƒ L(A)
crypto_auth_verify : ƒ K(A,e,a)
crypto_box_BEFORENMBYTES : 32
crypto_box_MACBYTES : 16
crypto_box_NONCEBYTES : 24
crypto_box_PUBLICKEYBYTES : 32
crypto_box_SEALBYTES : 48
crypto_box_SECRETKEYBYTES : 32
crypto_box_SEEDBYTES : 32
crypto_box_beforenm : ƒ P(A,e,a)
crypto_box_detached : ƒ V(A,e,a,t,I)
crypto_box_easy : ƒ T(A,e,a,t,I)
crypto_box_easy_afternm : ƒ j(A,e,a,t)
crypto_box_keypair : ƒ W(A)
crypto_box_open_detached : ƒ z(A,e,a,t,I,r)
crypto_box_open_easy : ƒ Z(A,e,a,t,I)
crypto_box_open_easy_afternm : ƒ q(A,e,a,t)
crypto_box_seal : ƒ O(A,e,a)
crypto_box_seal_open : ƒ $(A,e,a,t)
crypto_box_seed_keypair : ƒ AA(A,e)
crypto_core_hchacha20_CONSTBYTES : 16
crypto_core_hchacha20_INPUTBYTES : 16
crypto_core_hchacha20_KEYBYTES : 32
crypto_core_hchacha20_OUTPUTBYTES : 32
crypto_generichash : ƒ eA(A,e,a,t)
crypto_generichash_BYTES : 32
crypto_generichash_BYTES_MAX : 64
crypto_generichash_BYTES_MIN : 16
crypto_generichash_KEYBYTES : 32
crypto_generichash_KEYBYTES_MAX : 64
crypto_generichash_KEYBYTES_MIN : 16
crypto_generichash_final : ƒ aA(A,e,a)
crypto_generichash_init : ƒ tA(A,e,a)
crypto_generichash_keygen : ƒ IA(A)
crypto_generichash_update : ƒ rA(A,e,a)
crypto_hash : ƒ gA(A,e)
crypto_hash_BYTES : 64
crypto_hash_sha256 : ƒ _A(A,e)
crypto_hash_sha256_BYTES : 32
crypto_hash_sha512 : ƒ oA(A,e)
crypto_hash_sha512_BYTES : 64
crypto_kdf_BYTES_MAX : 64
crypto_kdf_BYTES_MIN : 16
crypto_kdf_CONTEXTBYTES : 8
crypto_kdf_KEYBYTES : 32
crypto_kdf_derive_from_key : ƒ cA(A,e,t,I,r)
crypto_kdf_keygen : ƒ iA(A)
crypto_kx_PUBLICKEYBYTES : 32
crypto_kx_SECRETKEYBYTES : 32
crypto_kx_SEEDBYTES : 32
crypto_kx_SESSIONKEYBYTES : 32
crypto_kx_client_session_keys : ƒ nA(A,e,a,t)
crypto_kx_keypair : ƒ BA(A)
crypto_kx_seed_keypair : ƒ sA(A,e)
crypto_kx_server_session_keys : ƒ yA(A,e,a,t)
crypto_onetimeauth : ƒ CA(A,e,a)
crypto_onetimeauth_BYTES : 16
crypto_onetimeauth_KEYBYTES : 32
crypto_onetimeauth_final : ƒ hA(A,e)
crypto_onetimeauth_init : ƒ QA(A,e)
crypto_onetimeauth_keygen : ƒ EA(A)
crypto_onetimeauth_update : ƒ pA(A,e,a)
crypto_onetimeauth_verify : ƒ lA(A,e,a)
crypto_pwhash : ƒ fA(A,e,a,t,I,r,g)
crypto_pwhash_ALG_ARGON2I13 : 1
crypto_pwhash_ALG_ARGON2ID13 : 2
crypto_pwhash_ALG_DEFAULT : 2
crypto_pwhash_BYTES_MAX : -1
crypto_pwhash_BYTES_MIN : 16
crypto_pwhash_MEMLIMIT_INTERACTIVE : 67108864
crypto_pwhash_MEMLIMIT_MAX : -2147483648
crypto_pwhash_MEMLIMIT_MIN : 8192
crypto_pwhash_MEMLIMIT_MODERATE : 268435456
crypto_pwhash_MEMLIMIT_SENSITIVE : 1073741824
crypto_pwhash_OPSLIMIT_INTERACTIVE : 2
crypto_pwhash_OPSLIMIT_MAX : -1
crypto_pwhash_OPSLIMIT_MIN : 1
crypto_pwhash_OPSLIMIT_MODERATE : 3
crypto_pwhash_OPSLIMIT_SENSITIVE : 4
crypto_pwhash_PASSWD_MAX : -1
crypto_pwhash_PASSWD_MIN : 0
crypto_pwhash_SALTBYTES : 16
crypto_pwhash_STRBYTES : 128
crypto_pwhash_STRPREFIX : "$argon2id$"
crypto_pwhash_STR_VERIFY : -1
crypto_pwhash_scryptsalsa208sha256 : ƒ uA(A,e,a,t,I,r)
crypto_pwhash_scryptsalsa208sha256_BYTES_MAX : -1
crypto_pwhash_scryptsalsa208sha256_BYTES_MIN : 16
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE : 16777216
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX : -1
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN : 16777216
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE : 1073741824
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE : 524288
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX : -1
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN : 32768
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE : 33554432
crypto_pwhash_scryptsalsa208sha256_SALTBYTES : 32
crypto_pwhash_scryptsalsa208sha256_STRBYTES : 102
crypto_pwhash_scryptsalsa208sha256_STRPREFIX : "$7$"
crypto_pwhash_scryptsalsa208sha256_STR_VERIFY : -1
crypto_pwhash_scryptsalsa208sha256_ll : ƒ wA(A,e,a,t,I,r,g)
crypto_pwhash_scryptsalsa208sha256_str : ƒ bA(A,e,a,t)
crypto_pwhash_scryptsalsa208sha256_str_verify : ƒ dA(A,e,t)
crypto_pwhash_str : ƒ DA(A,e,a,t)
crypto_pwhash_str_verify : ƒ mA(A,e,t)
crypto_scalarmult : ƒ kA(A,e,a)
crypto_scalarmult_BYTES : 32
crypto_scalarmult_SCALARBYTES : 32
crypto_scalarmult_base : ƒ FA(A,e)
crypto_secretbox_KEYBYTES : 32
crypto_secretbox_MACBYTES : 16
crypto_secretbox_NONCEBYTES : 24
crypto_secretbox_detached : ƒ vA(A,e,a,t)
crypto_secretbox_easy : ƒ MA(A,e,a,t)
crypto_secretbox_keygen : ƒ GA(A)
crypto_secretbox_open_detached : ƒ NA(A,e,a,t,I)
crypto_secretbox_open_easy : ƒ YA(A,e,a,t)
crypto_secretstream_xchacha20poly1305_ABYTES : 17
crypto_secretstream_xchacha20poly1305_HEADERBYTES : 24
crypto_secretstream_xchacha20poly1305_KEYBYTES : 32
crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX : -1
crypto_secretstream_xchacha20poly1305_TAG_FINAL : 3
crypto_secretstream_xchacha20poly1305_TAG_MESSAGE : 0
crypto_secretstream_xchacha20poly1305_TAG_PUSH : 1
crypto_secretstream_xchacha20poly1305_TAG_REKEY : 2
crypto_secretstream_xchacha20poly1305_init_pull : ƒ HA(A,e,a)
crypto_secretstream_xchacha20poly1305_init_push : ƒ xA(A,e)
crypto_secretstream_xchacha20poly1305_keygen : ƒ SA(A)
crypto_secretstream_xchacha20poly1305_pull : ƒ RA(A,e,a,t)
crypto_secretstream_xchacha20poly1305_push : ƒ JA(A,e,a,t,I)
crypto_secretstream_xchacha20poly1305_rekey : ƒ XA(A,e)
crypto_shorthash : ƒ UA(A,e,a)
crypto_shorthash_BYTES : 8
crypto_shorthash_KEYBYTES : 16
crypto_shorthash_keygen : ƒ LA(A)
crypto_shorthash_siphashx24 : ƒ KA(A,e,a)
crypto_shorthash_siphashx24_BYTES : 16
crypto_shorthash_siphashx24_KEYBYTES : 16
crypto_sign : ƒ PA(A,e,a)
crypto_sign_BYTES : 64
crypto_sign_PUBLICKEYBYTES : 32
crypto_sign_SECRETKEYBYTES : 64
crypto_sign_SEEDBYTES : 32
crypto_sign_detached : ƒ VA(A,e,a)
crypto_sign_ed25519_pk_to_curve25519 : ƒ TA(A,e)
crypto_sign_ed25519_sk_to_curve25519 : ƒ jA(A,e)
crypto_sign_ed25519_sk_to_pk : ƒ WA(A,e)
crypto_sign_ed25519_sk_to_seed : ƒ zA(A,e)
crypto_sign_final_create : ƒ ZA(A,e,a)
crypto_sign_final_verify : ƒ qA(A,e,a,t)
crypto_sign_init : ƒ OA(A)
crypto_sign_keypair : ƒ $A(A)
crypto_sign_open : ƒ Ae(A,e,a)
crypto_sign_seed_keypair : ƒ ee(A,e)
crypto_sign_update : ƒ ae(A,e,a)
crypto_sign_verify_detached : ƒ te(A,e,a)
crypto_stream_KEYBYTES : 32
crypto_stream_NONCEBYTES : 24
crypto_stream_chacha20_KEYBYTES : 32
crypto_stream_chacha20_NONCEBYTES : 8
crypto_stream_chacha20_ietf_KEYBYTES : 32
crypto_stream_chacha20_ietf_NONCEBYTES : 12
crypto_stream_chacha20_ietf_xor : ƒ Ie(A,e,a,t)
crypto_stream_chacha20_ietf_xor_ic : ƒ re(A,e,a,t,I)
crypto_stream_chacha20_keygen : ƒ ge(A)
crypto_stream_chacha20_xor : ƒ _e(A,e,a,t)
crypto_stream_chacha20_xor_ic : ƒ oe(A,e,a,t,I)
crypto_stream_keygen : ƒ ce(A)
crypto_stream_xchacha20_KEYBYTES : 32
crypto_stream_xchacha20_NONCEBYTES : 24
crypto_stream_xchacha20_keygen : ƒ ie(A)
crypto_stream_xchacha20_xor : ƒ ne(A,e,a,t)
crypto_stream_xchacha20_xor_ic : ƒ Be(A,e,a,t,I)
from_base64 : ƒ (A,e)
from_hex : ƒ (A)
from_string : ƒ a(A)
increment : ƒ (A)
is_zero : ƒ (A)
libsodium : {onAbort: ƒ, onRuntimeInitialized: ƒ, read: ƒ, readAsync: ƒ, arguments: Arguments(2), …}
memcmp : ƒ (A,e)
memzero : ƒ (A)
output_formats : ƒ _()
pad : ƒ (A,e)
randombytes_SEEDBYTES : 32
randombytes_buf : ƒ se(A,e)
randombytes_buf_deterministic : ƒ ye(A,e,a)
randombytes_close : ƒ Ce(A)
randombytes_random : ƒ he(A)
randombytes_stir : ƒ Ee(A)
randombytes_uniform : ƒ pe(A,e)
ready : Promise {<resolved>: undefined}
sodium_version_string : ƒ le()
symbols : ƒ ()
to_base64 : ƒ g(A,e)
to_hex : ƒ I(A)
to_string : ƒ t(A)
unpad : ƒ (A,e)
__proto__ : Object
*)
