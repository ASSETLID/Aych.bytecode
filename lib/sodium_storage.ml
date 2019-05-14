open Js_of_ocaml

type bigbytes = (* Typed_array.Bigstring.t *)
  (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

type jstype = Typed_array.uint8Array Js.t

let bytes_of_js u =
  let l = u##length in
  let b = Bytes.create l in
  for i = 0 to l - 1 do
    Bytes.set b i (Char.unsafe_chr (Typed_array.unsafe_get u i))
  done;
  b

let js_of_bytes b =
  let l = Bytes.length b in
  let u = jsnew Typed_array.uint8Array (l) in
  Bytes.iteri (fun i c ->
      Typed_array.set u i (Char.code c)
    ) b;
  u

module type S = sig
  type t

  val create     : int -> t
  val zero       : t -> int -> int -> unit
  val blit       : t -> int -> t -> int -> int -> unit
  val sub        : t -> int -> int -> t
  val length     : t -> int
  val to_js      : t -> jstype
  val of_js      : jstype -> t
  val to_bytes   : t -> Bytes.t
  val of_bytes   : Bytes.t -> t
end

module Bigbytes = struct
  type t = bigbytes

  open Bigarray

  let create     len = (Array1.create char c_layout len)
  let length     str = Array1.dim str
  let zero       str pos len = (Array1.fill (Array1.sub str pos len) '\x00')

  let to_js str =
    jsnew Typed_array.uint8Array_fromBuffer
      (Typed_array.Bigstring.to_arrayBuffer str)

  let of_js j =
    Typed_array.Bigstring.of_arrayBuffer j##buffer

  let to_bytes str =
    let str' = Bytes.create (Array1.dim str) in
    Bytes.iteri (fun i _ -> Bytes.set str' i (Array1.unsafe_get str i)) str';
    str'

  let of_bytes str =
    let str' = create (Bytes.length str) in
    Bytes.iteri (Array1.unsafe_set str') str;
    str'

  let sub = Array1.sub

  let blit src srcoff dst dstoff len =
    Array1.blit (Array1.sub src srcoff len)
                (Array1.sub dst dstoff len)
end

module Bytes = struct
  type t = Bytes.t

  let create     len = Bytes.create len
  let length     byt = Bytes.length byt
  let zero       byt pos len = Bytes.fill byt pos len '\x00'

  let to_js      byt = js_of_bytes byt
  let of_js      j   = bytes_of_js j
  let to_bytes   byt = Bytes.copy byt
  let of_bytes   byt = Bytes.copy byt
  let sub            = Bytes.sub
  let blit           = Bytes.blit
end
