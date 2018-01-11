
open Jstest.Console
open Sodium

let add_byte b = Bytes.concat (Bytes.of_string "") [b; Bytes.of_string "\x00"]

let message = Bytes.of_string "The quick brown fox jumps over the lazy dog"

let test_digest ctxt =
  assert (Generichash.primitive = "blake2b");
  let hash  = Generichash.Bytes.digest message in
  let hash' = "\001q\140\2365\205=ym\208\000 \224\191\236\180s\173#E}"^
              "\006;u\239\242\156\015\250.X\169" in
  assert_equal __LOC__ (Bytes.of_string hash') (Generichash.Bytes.of_hash hash);
  let hash  = Generichash.(Bytes.digest ~size:size_min message) in
  let hash' = "$\157\249\164\159Q}\220\211\127\\\137v \236s" in
  assert_equal __LOC__ (Bytes.of_string hash') (Generichash.Bytes.of_hash hash);
  let hash  = Generichash.(Bytes.digest ~size:size_max message) in
  let hash' = "\168\173\212\189\221\253\147\228\135}'F\230(\023\177"^
              "\0226J\031\167\188\020\141\149\t\011\1993;6s\248$\001"^
              "\207z\162\228\203\030\205\144)n?\020\203T\019\248\237"^
              "w\190s\004[\019\145L\220\214\169\024" in
  assert_equal __LOC__ (Bytes.of_string hash') (Generichash.Bytes.of_hash hash);

  let key = Generichash.Bytes.to_key (Bytes.of_string "SUPER SECRET KEY") in
  let hash = Generichash.Bytes.digest_with_key key message in
  let hash' = "\174m\018\173\1916\138\b`\227,\184QS\178 ZT\004\213\216"^
              "\171\227\152\ty\127\158\139\166\206\240" in
  assert_equal __LOC__ (Bytes.of_string hash') (Generichash.Bytes.of_hash hash);

  let key = Generichash.Bytes.to_key (Bytes.of_string "DUPER SECRET KEY") in
  let hash = Generichash.Bytes.digest_with_key key message in
  let hash' = "C\2120-\239R\003\243\233X\207M\187\242\244?\164\130\219"^
              ">\206QTR\031\230\188\252\167\027%\136" in
  assert_equal __LOC__ (Bytes.of_string hash') (Generichash.Bytes.of_hash hash)

let test_serialize ctxt =
  let hash = Generichash.Bytes.digest message in
  assert_equal __LOC__
    (Generichash.Bytes.(of_hash @@ to_hash @@ of_hash @@ hash))
    (Generichash.Bytes.of_hash hash);
  assert_equal __LOC__
    (Generichash.Bigbytes.(of_hash @@ to_hash @@ of_hash @@ hash))
    (Generichash.Bigbytes.of_hash hash);
  ()

let test_equal ctxt =
  let size = Generichash.size_default in
  let h   = Bytes.of_string (String.make size 'A') in
  let h'  = Bytes.of_string ("B" ^ (String.make (size - 1) 'A')) in
  let h'' = Bytes.of_string ((String.make (size - 1) 'A') ^ "B") in
  assert_bool __LOC__ "=" (0 = Generichash.compare
                     (Generichash.Bytes.to_hash h)
                     (Generichash.Bytes.to_hash h));
  assert_bool __LOC__ "<>" (0 <> Generichash.compare
                      (Generichash.Bytes.to_hash h)
                      (Generichash.Bytes.to_hash h'));
  assert_bool __LOC__ "<>" (0 <> Generichash.compare
                      (Generichash.Bytes.to_hash h)
                      (Generichash.Bytes.to_hash h''))

let test_exn ctxt =
  let too_small = Bytes.create (Generichash.size_min - 1) in
  assert_raises __LOC__ (Size_mismatch "Generichash.to_hash")
    (fun () -> Generichash.Bytes.to_hash too_small);
  let too_big = Bytes.create (Generichash.size_max + 1) in
  assert_raises __LOC__ (Size_mismatch "Generichash.to_hash")
    (fun () -> Generichash.Bytes.to_hash too_big);
  let too_small = Bytes.create (Generichash.key_size_min - 1) in
  assert_raises __LOC__ (Size_mismatch "Generichash.to_key")
    (fun () -> Generichash.Bytes.to_key too_small);
  let too_big = Bytes.create (Generichash.key_size_max + 1) in
  assert_raises __LOC__ (Size_mismatch "Generichash.to_key")
    (fun () -> Generichash.Bytes.to_key too_big);
  assert_raises __LOC__ (Size_mismatch "Generichash.init")
    (fun () -> Generichash.(init ~size:(size_min - 1) ()));
  assert_raises __LOC__ (Size_mismatch "Generichash.init")
    (fun () -> Generichash.(init ~size:(size_max + 1) ()))

let test_streaming ctxt =
  let empty = Bytes.of_string "" in

  let direct_hash = Generichash.Bytes.digest empty in
  let state = Generichash.init () in
  let staged_hash = Generichash.final state in
  assert_bool __LOC__ "simple staged" (0 = Generichash.compare direct_hash staged_hash);

  let key = Generichash.Bytes.to_key (Bytes.of_string "SUPER SECRET KEY") in
  let direct_hash = Generichash.Bytes.digest_with_key key empty in
  let state = Generichash.init ~key () in
  let staged_hash = Generichash.final state in
  assert_bool __LOC__ "keyed staged" (0 = Generichash.compare direct_hash staged_hash);

  assert_raises __LOC__ (Already_finalized "Generichash.final")
    (fun () -> Generichash.final state);

  assert_raises __LOC__ (Already_finalized "Generichash.update")
    (fun () -> Generichash.Bytes.update state (Bytes.of_string "lalala"));

  let direct_hash = Generichash.(Bytes.digest ~size:size_max empty) in
  let state = Generichash.(init ~size:size_max ()) in
  let staged_hash = Generichash.final state in
  assert_bool __LOC__ "size_max staged"
    (0 = Generichash.compare direct_hash staged_hash);

  let direct_hash = Generichash.(Bytes.digest message) in
  let state = Generichash.init () in
  let () = Generichash.Bytes.update state message in
  let staged_hash = Generichash.final state in
  assert_bool __LOC__ "message staged"
    (0 = Generichash.compare direct_hash staged_hash);

  (* let hstate = Generichash.init () in
   * let hello = Bytes.of_string "hello" in
   * let () = Generichash.Bytes.update hstate hello in
   * let hwstate = Generichash.copy hstate in
   * let world = Bytes.of_string " world" in
   * let hello_world = Bytes.cat hello world in
   * let () = Generichash.Bytes.update hwstate world in
   * let h = Generichash.final hstate in
   * let hw = Generichash.final hwstate in
   * assert_bool __LOC__ "copy stream 1"
   *   (0 = Generichash.compare (Generichash.Bytes.digest hello) h);
   * assert_bool __LOC__ "copy stream 2"
   *   (0 = Generichash.compare (Generichash.Bytes.digest hello_world) hw) *);
  ()

let _ = "Generichash" >::: [
    "test_digest"    >:: test_digest;
    "test_serialize" >:: test_serialize;
    "test_equal"     >:: test_equal;
    "test_exn"       >:: test_exn;
    "test_streaming" >:: test_streaming;
  ]


let test_equal_public_keys ctxt =
  let pk   = Bytes.of_string (String.make (Sign.public_key_size) 'A') in
  let pk'  = Bytes.of_string ("B" ^ (String.make (Sign.public_key_size - 1) 'A')) in
  let pk'' = Bytes.of_string ((String.make (Sign.public_key_size - 1) 'A') ^ "B") in
  assert_bool __LOC__ "=" (Sign.equal_public_keys (Sign.Bytes.to_public_key pk)
                                          (Sign.Bytes.to_public_key pk));
  assert_bool __LOC__ "<>" (not (Sign.equal_public_keys (Sign.Bytes.to_public_key pk)
                                                (Sign.Bytes.to_public_key pk')));
  assert_bool __LOC__ "<>" (not (Sign.equal_public_keys (Sign.Bytes.to_public_key pk)
                                                (Sign.Bytes.to_public_key pk'')))

let test_equal_secret_keys ctxt =
  let sk   = Bytes.of_string (String.make (Sign.secret_key_size) 'A') in
  let sk'  = Bytes.of_string ("B" ^ (String.make (Sign.secret_key_size - 1) 'A')) in
  let sk'' = Bytes.of_string ((String.make (Sign.secret_key_size - 1) 'A') ^ "B") in
  assert_bool __LOC__ "=" (Sign.equal_secret_keys (Sign.Bytes.to_secret_key sk)
                                          (Sign.Bytes.to_secret_key sk));
  assert_bool __LOC__ "<>" (not (Sign.equal_secret_keys (Sign.Bytes.to_secret_key sk)
                                                (Sign.Bytes.to_secret_key sk')));
  assert_bool __LOC__ "<>" (not (Sign.equal_secret_keys (Sign.Bytes.to_secret_key sk)
                                                (Sign.Bytes.to_secret_key sk'')))

let test_compare_public_keys ctxt =
  let pk   = Bytes.of_string (String.make (Sign.public_key_size) 'A') in
  let pk'  = Bytes.of_string ((String.make (Sign.public_key_size - 1) 'A') ^ "0") in
  let pk'' = Bytes.of_string ("B" ^ (String.make (Sign.public_key_size - 1) 'A')) in
  assert_equal __LOC__ 0    (Sign.compare_public_keys (Sign.Bytes.to_public_key pk)
                                    (Sign.Bytes.to_public_key pk));
  assert_equal __LOC__ 1    (Sign.compare_public_keys (Sign.Bytes.to_public_key pk)
                                    (Sign.Bytes.to_public_key pk'));
  assert_equal __LOC__ (-1) (Sign.compare_public_keys (Sign.Bytes.to_public_key pk)
                                    (Sign.Bytes.to_public_key pk''));
  ()

let test_permute ctxt =
  let (sk, pk) = Sign.random_keypair () in
  assert_raises __LOC__ (Size_mismatch "Sign.to_public_key")
                (fun () -> (Sign.Bytes.to_public_key (add_byte (Sign.Bytes.of_public_key pk))));
  assert_raises __LOC__ (Size_mismatch "Sign.to_secret_key")
                (fun () -> (Sign.Bytes.to_secret_key (add_byte (Sign.Bytes.of_secret_key sk))))

let secret_message =
  Bytes.of_string "The cock flies with a mistaken DMCA takedown notice."

let setup () =
  Sign.random_keypair (), secret_message

let test_sign ctxt =
  let (sk, pk), msg = setup () in
  let smsg = Sign.Bytes.sign sk msg in
  let msg' = Sign.Bytes.sign_open pk smsg in
  assert_equal __LOC__ msg msg'

let test_sign_fail_permute ctxt =
  let (sk, pk), msg = setup () in
  let smsg = Sign.Bytes.sign sk msg in
  Bytes.set smsg 10 'a';
  assert_raises __LOC__ Verification_failure
                (fun () -> ignore (Sign.Bytes.sign_open pk smsg))

let test_sign_fail_key ctxt =
  let (sk, pk), msg = setup () in
  let (sk',pk') = Sign.random_keypair () in
  let smsg = Sign.Bytes.sign sk msg in
  assert_raises __LOC__ Verification_failure
                (fun () -> ignore (Sign.Bytes.sign_open pk' smsg))

let test_sign_detached ctxt =
  let (sk, pk), msg = setup () in
  let sign = Sign.Bytes.sign_detached sk msg in
  Sign.Bytes.verify pk sign msg;
  assert_bool __LOC__ "verfiy" true

let test_sign_detached_fail_permute ctxt =
  let (sk, pk), msg = setup () in
  let sign = Sign.Bytes.sign_detached sk msg in
  let sign' = Sign.Bytes.of_signature sign in
  Bytes.set sign' 10 'a';
  let sign = Sign.Bytes.to_signature sign' in
  assert_raises __LOC__ Verification_failure
                (fun () -> ignore (Sign.Bytes.verify pk sign msg))

let test_sign_detached_fail_permute_msg ctxt =
  let (sk, pk), msg = setup () in
  let sign = Sign.Bytes.sign_detached sk msg in
  Bytes.set msg 10 'a';
  assert_raises __LOC__ Verification_failure
                (fun () -> ignore (Sign.Bytes.verify pk sign msg))

let test_sign_detached_fail_key ctxt =
  let (sk, pk), msg = setup () in
  let (sk',pk') = Sign.random_keypair () in
  let sign = Sign.Bytes.sign_detached sk msg in
  assert_raises __LOC__ Verification_failure
                (fun () -> ignore (Sign.Bytes.verify pk' sign msg))

(* let test_sign_seed ctxt =
 *   let seed_str = Random.Bytes.generate Sign.seed_size in
 *   let seed = Sign.Bytes.to_seed seed_str in
 *   let (sk, pk) = Sign.seed_keypair seed in
 *   (\* In actual use, we would probably zero both seed values here. *\)
 *   let smsg = Sign.Bytes.sign sk secret_message in
 *   let msg' = Sign.Bytes.sign_open pk smsg in
 *   assert_equal __LOC__ secret_message msg';
 *   let seed' = Sign.secret_key_to_seed sk in
 *   let seed_str' = Sign.Bytes.of_seed seed' in
 *   assert_equal __LOC__ seed_str seed_str';
 *   let pk' = Sign.secret_key_to_public_key sk in
 *   assert_bool __LOC__ "=" (Sign.equal_public_keys pk pk') *)

let _ = "Sign" >::: [
    "test_equal_public_keys"   >:: test_equal_public_keys;
    "test_equal_secret_keys"   >:: test_equal_secret_keys;
    "test_compare_public_keys" >:: test_compare_public_keys;
    "test_permute"             >:: test_permute;
    "test_sign"                >:: test_sign;
    "test_sign_fail_permute"   >:: test_sign_fail_permute;
    "test_sign_fail_key"       >:: test_sign_fail_key;
    "test_sign_detached"       >:: test_sign_detached;
    "test_sign_detached_fail_permute" >:: test_sign_detached_fail_permute;
    "test_sign_detached_fail_permute_msg" >:: test_sign_detached_fail_permute_msg;
    "test_sign_detached_fail_key" >:: test_sign_detached_fail_key;
    (* "test_sign_seed"           >:: test_sign_seed; *)
  ]
