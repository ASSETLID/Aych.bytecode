
(** Raised when message authentication fails. *)
exception Verification_failure

(** Raised when attempting to deserialize a malformed key, nonce, or
    attempting to use a bad hash length. *)
exception Size_mismatch of string

(** Raised when attempting to finalize an already finalized stream state. *)
exception Already_finalized of string

type secret
type public

type bigbytes =
  (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t


module Random : sig
  val stir : unit -> unit

  module type S = sig
    type storage
    val generate : int -> storage
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end


module Generichash : sig
  type hash
  type state
  type 'a key
  type secret_key = secret key

  (** Primitive used by this implementation. Currently ["blake2b"]. *)
  val primitive        : string

  (** [wipe_key k] overwrites [k] with zeroes. *)
  val wipe_key         : secret key -> unit

  (** Default recommended output size, in bytes. *)
  val size_default     : int

  (** Minimum supported output size, in bytes. *)
  val size_min         : int

  (** Maximum supported output size, in bytes. *)
  val size_max         : int

  (** [size_of_hash hash] is the size, in bytes, of the {!hash} [hash]. *)
  val size_of_hash     : hash -> int

  (** [compare h h'] is 0 if [h] and [h'] are equal, a negative
      integer if [h] is less than [h'], and a positive integer if [h]
      is greater than [h']. [compare] {i {b is not constant time}}. *)
  val compare          : hash -> hash -> int

  (** Default recommended key size, in bytes. *)
  val key_size_default : int

  (** Minimum supported key size, in bytes. *)
  val key_size_min     : int

  (** Maximum supported key size, in bytes. *)
  val key_size_max     : int

  (** [size_of_key key] is the size, in bytes, of the {!key} [key]. *)
  val size_of_key      : secret key -> int

  (** [random_key ()] generates a random secret key of
      {!key_size_default} bytes. *)
  val random_key       : unit -> secret key

  (** [init ?key ?size ()] is a streaming hash state keyed with [key]
      if supplied and computing a hash of size [size] (default
      {!size_default}).
      @raise Size_mismatch if [size] is greater than {!size_max} or
      less than {!size_min} *)
  val init             : ?key:secret key -> ?size:int -> unit -> state

  (** [final state] is the final hash of the inputs collected in
      [state].
      @raise Already_finalized if [state] has already had [final]
      applied to it *)
  val final            : state -> hash

  module type S = sig
    type storage

    (** [of_hash h] converts [h] to {!storage}. The result
        is [size_of_hash h] bytes long. *)
    val of_hash    : hash -> storage

    (** [to_hash s] converts [s] to a hash.
        @raise Size_mismatch if [s] is greater than {!size_max} or
        less than {!size_min} bytes long *)
    val to_hash    : storage -> hash

    (** [of_key k] converts key [k] to {!storage}. The result is
        [size_of_key k] bytes long. *)
    val of_key     : secret key -> storage

    (** [to_key s] converts [s] to a {!secret} {!key}.
        @raise Size_mismatch if [s] is greater than {!key_size_max} or
        less than {!key_size_min} bytes long *)
    val to_key     : storage -> secret key

    (** [digest ?size m] computes a hash of size [size] (default
        {!size_default}) for message [m]. *)
    val digest     : ?size:int -> storage -> hash

    (** [digest_with_key key m] computes a hash of size [size]
        (default {!size_default} keyed by [key] for message [m]. *)
    val digest_with_key : secret key -> ?size:int -> storage -> hash

    (** [update state m] updates the {!state} [state] with input [m].
        @raise Already_finalized if [state] has already had {!final}
        applied to it *)
    val update     : state -> storage -> unit
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end


module Sign : sig
  type 'a key
  type secret_key = secret key
  type public_key = public key
  type keypair = secret key * public key
  type signature
  type seed

  (** Primitive used by this implementation. Currently ["ed25519"]. *)
  val primitive           : string

  (** Size of public keys, in bytes. *)
  val public_key_size     : int

  (** Size of secret keys, in bytes. *)
  val secret_key_size     : int

  (** Size of signatures, in bytes. *)
  val signature_size      : int

  (** Size of signing key seeds, in bytes. *)
  val seed_size           : int

  (** [random_keypair ()] generates a random key pair. *)
  val random_keypair      : unit -> keypair

  (** [seed_keypair seed] generates a key pair from secret [seed]. *)
  val seed_keypair        : seed -> keypair

  (** [secret_key_to_seed sk] extracts the secret key [sk]'s {!seed}. *)
  val secret_key_to_seed  : secret key -> seed

  (** [secret_key_to_public_key sk] extract the secret key [sk]'s
      {!public_key}. *)
  val secret_key_to_public_key : secret key -> public key

  (** [wipe_key k] overwrites [k] with zeroes. *)
  val wipe_key            : 'a key -> unit

  (** [equal_public_keys a b] checks [a] and [b] for equality in constant
      time. *)
  val equal_public_keys   : public key -> public key -> bool

  (** [equal_secret_keys a b] checks [a] and [b] for equality in constant
      time. *)
  val equal_secret_keys   : secret key -> secret key -> bool

  (** [compare_public_keys a b] compares [a] and [b]. *)
  val compare_public_keys : public key -> public key -> int

  module type S = sig
    type storage

    (** [of_public_key k] converts [k] to {!storage}. The result is
        {!public_key_size} bytes long. *)
    val of_public_key   : public key -> storage

    (** [to_public_key s] converts [s] to a public key.
        @raise Size_mismatch if [s] is not {!public_key_size} bytes
        long *)
    val to_public_key   : storage -> public key

    (** [of_secret_key k] converts [k] to {!storage}. The result is
        {!secret_key_size} bytes long. *)
    val of_secret_key   : secret key -> storage

    (** [to_secret_key s] converts [s] to a secret key.
        @raise Size_mismatch if [s] is not {!secret_key_size} bytes
        long *)
    val to_secret_key   : storage -> secret key

    (** [of_signature a] converts [a] to {!storage}. The result is
        {!signature_size} bytes long. *)
    val of_signature    : signature -> storage

    (** [to_signature s] converts [s] to a signature.
        @raise Size_mismatch if [s] is not {!signature_size} bytes long *)
    val to_signature    : storage -> signature

    (** [of_seed s] converts [s] to type {!storage}. The result is
        {!seed_size} bytes long. *)
    val of_seed         : seed -> storage

    (** [to_seed s] converts [s] to a seed.
        @raise Size_mismatch if [s] is not {!seed_size} bytes long *)
    val to_seed         : storage -> seed

    (** [sign sk m] signs a message [m] using the signer's secret key [sk],
        and returns the resulting signed message. *)
    val sign            : secret key -> storage -> storage

    (** [sign_open pk sm] verifies the signature in [sm] using the signer's
        public key [pk], and returns the message.
        @raise Verification_failure if authenticity of message cannot
        be verified *)
    val sign_open       : public key -> storage -> storage

    (** [sign_detached sk m] signs a message [m] using the signer's secret
        key [sk], and returns the signature. *)
    val sign_detached   : secret key -> storage -> signature

    (** [verify pk s m] checks that [s] is a correct signature of a message
        [m] under the public key [pk].
        @raise Verification_failure if [s] is not a correct signature
        of [m] under [pk] *)
    val verify          : public key -> signature -> storage -> unit
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end


module Hash : sig
  type hash

  (** Primitive used by this implementation. Currently ["sha512"]. *)
  val primitive : string

  (** Size of hashes, in bytes. *)
  val size      : int

  (** [equal a b] checks [a] and [b] for equality in constant time. *)
  val equal     : hash -> hash -> bool

  module type H = sig
    type storage

    (** Primitive used by this implementation. Currently ["sha512"]. *)
    val primitive : string

    (** Size of hashes, in bytes. *)
    val size      : int

    (** [of_hash h] converts [h] to {!storage}. The result is {!size}
        bytes long. *)
    val of_hash : hash -> storage

    (** [to_hash s] converts [s] to a hash.
        @raise Size_mismatch if [s] is not {!size} bytes long *)
    val to_hash : storage -> hash

    (** [digest m] computes a hash for message [m]. *)
    val digest  : storage -> hash
  end

  module type S = sig
    include H
    module Sha256 : H with type storage = storage
    module Sha512 : H with type storage = storage
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end
