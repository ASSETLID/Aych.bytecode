open Js_of_ocaml
open Libsodium_js

(* Ensure required libraries are available *)
let js_failwith fmt =
  Format.kasprintf
    (fun s ->
       Js.raise_js_error (jsnew Js.error_constr (Js.string s)))
    fmt

let () =
  let is_node_js =
    Js.Optdef.test Js.Unsafe.global##module_ &&
    Js.Optdef.test Js.Unsafe.global##module_##exports
  in
  if not (Js.Optdef.test Js.Unsafe.global##sodium) then
    js_failwith "Library sodium is required but not available %s"
      (if is_node_js then
         "load it with:\n\
          const sodium = require('libsodium-wrappers-sumo');"
       else "")

let () =
  if not (Js.Optdef.test Js.Unsafe.global##sodium##crypto_sign_SEEDBYTES_) then
    js_failwith "Library sodium is not initialized"

let () =
  if not (Js.Optdef.test
            Js.Unsafe.global##sodium##crypto_sign_ed25519_sk_to_pk_) then
    js_failwith "Library libsodium-wrappers-sumo is required, it looks like \
                 only the non-sumo version is available."

let sodium : sodium Js.t = Js.Unsafe.global##sodium

exception Verification_failure
exception Size_mismatch of string
exception Already_finalized of string

type secret
type public

module Storage = Sodium_storage
type bigbytes = Storage.bigbytes

module Random = struct

  let stir () = sodium##randombytes_stir_(())

  module type S = sig
    type storage
    val generate      : int -> storage
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let generate size =
      sodium##randombytes_buf_(size)
      |> T.of_js

  end

  module Bytes = Make(Storage.Bytes)
  module Bigbytes = Make(Storage.Bigbytes)
end

module Generichash = struct
  type hash = Typed_array.uint8Array Js.t (* Bytes.t *)
  type 'a key = Typed_array.uint8Array Js.t (* Bytes.t *)
  type secret_key = secret key
  type state = {
    ptr  : generichash_state;
    size : int;
    mutable final : bool;
  }
  (* type state = generichash_state *)

  let primitive = "blake2b"

  let size_default = sodium##crypto_generichash_BYTES_
  let size_min = sodium##crypto_generichash_BYTES_MIN_
  let size_max = sodium##crypto_generichash_BYTES_MAX_
  let size_of_hash h = h##length

  let compare h1 h2 = sodium##compare(h1, h2) (* constant time *)

  let key_size_default = sodium##crypto_generichash_KEYBYTES_
  let key_size_min = sodium##crypto_generichash_KEYBYTES_MIN_
  let key_size_max = sodium##crypto_generichash_KEYBYTES_MAX_
  let size_of_key k = k##length

  let wipe_key k = sodium##memzero(k)

  let random_key () =
    sodium##crypto_generichash_keygen_(())

  let init ?(key=jsnew Typed_array.uint8Array (0)) ?(size=size_default) () =
    if size < size_min || size > size_max then
      raise (Size_mismatch "Generichash.init");
    let ptr = sodium##crypto_generichash_init_(key, size) in
    { ptr; size; final = false }

  (* let copy state =
   *   { state with ptr = Bytes.copy state.ptr } *)

  let final state =
    if state.final then raise (Already_finalized "Generichash.final")
    else begin
      state.final <- true;
      sodium##crypto_generichash_final_ (state.ptr, state.size)
    end


  module type S = sig

    type storage

    val of_hash : hash -> storage
    val to_hash : storage -> hash

    val of_key  : secret key -> storage
    val to_key  : storage -> secret key

    val digest          : ?size:int -> storage -> hash
    val digest_with_key : secret key -> ?size:int -> storage -> hash

    val update  : state -> storage -> unit
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let of_hash str =
      T.of_js str

    let to_hash str =
      let len = T.length str in
      if len < size_min || len > size_max then
        raise (Size_mismatch "Generichash.to_hash");
      T.to_js str

    let of_key str =
      T.of_js str

    let to_key str =
      let len = T.length str in
      if len < key_size_min || len > key_size_max then
        raise (Size_mismatch "Generichash.to_key");
      T.to_js str

    let digest_internal size key str =
      let str_js = T.to_js str in
      sodium##crypto_generichash_(size, str_js, key)

    let digest_with_key key ?(size=size_default) str =
      if size < size_min || size > size_max then
        raise (Size_mismatch "Generichash.digest_with_key");
      digest_internal size key str

    let digest ?(size=size_default) str =
      if size < size_min || size > size_max then
        raise (Size_mismatch "Generichash.digest");
      digest_internal size (jsnew Typed_array.uint8Array (0)) str

    let update state str =
      if state.final then raise (Already_finalized "Generichash.update")
      else
        sodium##crypto_generichash_update_ (state.ptr, T.to_js str)
  end

  module Bytes = Make(Storage.Bytes)
  module Bigbytes = Make(Storage.Bigbytes)

end


module Sign = struct

  type 'a key = Typed_array.uint8Array Js.t (* Bytes.t *)
  type secret_key = secret key
  type public_key = public key
  type keypair = secret key * public key
  type signature = Typed_array.uint8Array Js.t (* Bytes.t *)
  type seed = Typed_array.uint8Array Js.t (* Bytes.t *)

  let primitive = "ed25519"

  let public_key_size  = sodium##crypto_sign_PUBLICKEYBYTES_
  let secret_key_size  = sodium##crypto_sign_SECRETKEYBYTES_
  let signature_size   = sodium##crypto_sign_BYTES_
  let seed_size        = sodium##crypto_sign_SEEDBYTES_

  let random_keypair () =
    let pair = sodium##crypto_sign_keypair_ (()) in
    (pair##privateKey, pair##publicKey)

  let seed_keypair seed =
    let pair = sodium##crypto_sign_seed_keypair_ (seed) in
    (pair##privateKey, pair##publicKey)

  let secret_key_to_seed sk =
    sodium##crypto_sign_ed25519_sk_to_seed_ (sk)

  let secret_key_to_public_key sk =
    sodium##crypto_sign_ed25519_sk_to_pk_ (sk)

  let wipe_key k = sodium##memzero(k)

  let equal_public_keys pk1 pk2 = sodium##memcmp(pk1, pk2)
  let equal_secret_keys sk1 sk2 = sodium##memcmp(sk1, sk2)
  let compare_public_keys pk1 pk2 = sodium##compare(pk1, pk2)

  module type S = sig
    type storage

    val of_public_key   : public key -> storage
    val to_public_key   : storage -> public key

    val of_secret_key   : secret key -> storage
    val to_secret_key   : storage -> secret key

    val of_signature    : signature -> storage
    val to_signature    : storage -> signature

    val of_seed         : seed -> storage
    val to_seed         : storage -> seed

    val sign            : secret key -> storage -> storage
    val sign_open       : public key -> storage -> storage

    val sign_detached   : secret key -> storage -> signature
    val verify          : public key -> signature -> storage -> unit
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let verify_length str len fn_name =
      if T.length str <> len then raise (Size_mismatch fn_name)

    let of_public_key key =
      T.of_js key

    let to_public_key str =
      verify_length str public_key_size "Sign.to_public_key";
      T.to_js str

    let of_secret_key key =
      T.of_js key

    let to_secret_key str =
      verify_length str secret_key_size "Sign.to_secret_key";
      T.to_js str

    let of_signature sign =
      T.of_js sign

    let to_signature str =
      verify_length str signature_size "Sign.to_signature";
      T.to_js str

    let of_seed seed =
      T.of_js seed

    let to_seed str =
      verify_length str seed_size "Sign.to_seed";
      T.to_js str

    let sign skey message =
      sodium##crypto_sign_(T.to_js message, skey)
      |> T.of_js

    let sign_open pkey signed_msg =
      try
        sodium##crypto_sign_open_(T.to_js signed_msg, pkey)
        |> T.of_js
      with Js.Error _ -> raise Verification_failure

    let sign_detached skey message =
      sodium##crypto_sign_detached_(T.to_js message, skey)

    let verify pkey (signature:signature) message =
      let ret =
        sodium##crypto_sign_verify_detached_(signature, T.to_js message, pkey)
      in
      if not ret then raise Verification_failure
  end

  module Bytes = Make(Storage.Bytes)
  module Bigbytes = Make(Storage.Bigbytes)

end


module Hash = struct
  type hash = Typed_array.uint8Array Js.t (* Bytes.t *)

  let primitive = "sha512"

  let size = sodium##crypto_hash_BYTES_

  let equal h1 h2 = sodium##memcmp(h1, h2)

  module type H = sig
    type storage
    val primitive : string
    val size : int
    val of_hash : hash -> storage
    val to_hash : storage -> hash
    val digest  : storage -> hash
  end

  module type S = sig
    include H
    module Sha256 : H with type storage = storage
    module Sha512 : H with type storage = storage
  end

  module Make(T: Storage.S) = struct
    type storage = T.t

    let primitive = primitive
    let size = size

    let of_hash str =
      T.of_js str

    let to_hash str =
      if T.length str <> size then
        raise (Size_mismatch "Hash.to_hash");
      T.to_js str

    let digest str =
      sodium##crypto_hash_(T.to_js str)

    module Sha256 = struct
      type storage = T.t
      let primitive = "sha256"
      let size = sodium##crypto_hash_sha256_BYTES_

      let of_hash str =
        T.of_js str

      let to_hash str =
        if T.length str <> size then
          raise (Size_mismatch "Hash.to_hash");
        T.to_js str

      let digest str =
        sodium##crypto_hash_sha256_(T.to_js str)
    end

    module Sha512 = struct
      type storage = T.t
      let primitive = "sha512"
      let size = sodium##crypto_hash_sha512_BYTES_

      let of_hash str =
        T.of_js str

      let to_hash str =
        if T.length str <> size then
          raise (Size_mismatch "Hash.to_hash");
        T.to_js str

      let digest str =
        sodium##crypto_hash_sha512_(T.to_js str)
    end

  end

  module Bytes = Make(Storage.Bytes)
  module Bigbytes = Make(Storage.Bigbytes)
end
