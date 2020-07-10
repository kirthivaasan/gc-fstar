module Spec.OT

open Lib.IntTypes
open Lib.RawIntTypes
open Lib.ByteSequence
open Lib.Sequence

module Curve = Spec.Curve25519
module HashSHA = Spec.SHA2
module Chacha = Spec.Chacha20Poly1305
module HashDef = Spec.Hash.Definitions
module H = Spec.Agile.Hash

inline_for_extraction let hash_size : size_nat = 32
inline_for_extraction let dh_key_size : size_nat = 32
inline_for_extraction let public_key_size = dh_key_size
inline_for_extraction let private_key_size = dh_key_size
inline_for_extraction let symmetric_key_size : size_nat = 16

type dh_key = lbytes dh_key_size
type public_key = lbytes public_key_size
type private_key = lbytes private_key_size
type symmetric_key = lbytes symmetric_key_size
type message = lbytes symmetric_key_size
type ciphertext = lbytes symmetric_key_size

let empty_aad = bytes_empty

val dh : private_key -> public_key -> Tot (option dh_key)
let dh s p =
  let output = Curve.scalarmult s p in
  let result : bool = not (lbytes_eq (create 32 (u8 0)) output)
  in
  if result then Some output else None

noeq type sender_messages = {
  m0 : message;
  m1 : message;
}

noeq type public_keypair = {
  pk0 : dh_key;
  pk1 : dh_key;
}

noeq type sender_ciphertexts = {
  c0 : (ciphertext & Chacha.tag);
  c1 : (ciphertext & Chacha.tag);
}

let add_ec_points q nq nqp1 =
  let x_1, z_1 = q in
  let x_2, z_2 = nq in
  let x_3, z_3 = nqp1 in
  let a = Curve.fadd x_2 z_2 in
  let b = Curve.fsub x_2 z_2 in
  let c = Curve.fadd x_3 z_3 in
  let d = Curve.fsub x_3 z_3 in
  let da = Curve.fmul d a in
  let cb = Curve.fmul c b in
  let da_cb = Curve.fadd da cb in
  let da_cb_squared = Curve.fmul da_cb da_cb in
  let x_5 = Curve.fmul z_1 da_cb_squared in
  let z_5 = Curve.fmul x_1 da_cb_squared in
  (x_5, z_5)

let sub_ec_points q np (nqp1:Curve.proj_point) =
  let x_3, z_3 = nqp1 in
  let felem_additive_inv = (Curve.fsub Curve.zero z_3) in
  add_ec_points q np (x_3 , felem_additive_inv)

val hash_pubkey : public_key -> Chacha.key
let hash_pubkey pb =
  H.hash HashDef.SHA2_256 pb

val receiver_compute_pubkey : private_key -> public_key -> bit_t -> public_key
let receiver_compute_pubkey receiver_privkey sender_pubkey receiver_bit =
  if receiver_bit = 0x0uy
  then (Curve.secret_to_public receiver_privkey)
  else
    let bigY = Curve.decodePoint (Curve.secret_to_public receiver_privkey) in
    let q = (bigY, Curve.one) in
    let nq = (Curve.one, Curve.zero) in
    let nqp1 = (bigY, Curve.one) in
    Curve.encodePoint (add_ec_points q nq nqp1)

val sender_compute_ot_keys : private_key -> public_key -> public_keypair
let sender_compute_ot_keys sender_privkey receiver_pubkey =
  let k0 = Curve.secret_to_public sender_privkey in
  let k1 =
    let bigY:nat = Curve.decodePoint receiver_pubkey in
    let q = (bigY, Curve.one) in
    let nq = (Curve.one, Curve.zero) in
    let nqp1 = (bigY, Curve.one) in
    Curve.encodePoint (sub_ec_points q nq nqp1) in
    {pk0=k0; pk1=k1}

val encrypt_sender_messages : public_keypair -> sender_messages -> Chacha.nonce ->  sender_ciphertexts
let encrypt_sender_messages pkpair smsgs testnonce =
  let k0 = hash_pubkey pkpair.pk0 in
  let k1 = hash_pubkey pkpair.pk1 in
  let enc0 = Chacha.aead_encrypt k0 testnonce smsgs.m0 empty_aad in
  let enc1 = Chacha.aead_encrypt k1 testnonce smsgs.m1 empty_aad in
  let cipher0 = Seq.slice enc0 0 16 in
  let cipher1 = Seq.slice enc1 0 16 in
  let mac0 = Seq.slice enc0 16 32 in
  let mac1 = Seq.slice enc0 16 32 in
  {c0=(cipher0, mac0); c1=(cipher1, mac1)}

val decrypt_sender_messages : public_key -> sender_ciphertexts -> Chacha.nonce -> option message
let decrypt_sender_messages pk sctxts n =
  let k = hash_pubkey pk in
  let (c0, t0) = sctxts.c0 in
  let (c1, t1) = sctxts.c1 in
  let dec0 = Chacha.aead_decrypt k n c0 t0 empty_aad in
  let dec1 = Chacha.aead_decrypt k n c1 t1 empty_aad in
  match dec0, dec1 with
  | Some _, Some _ -> None
  | Some _, None -> dec0
  | None, Some _ -> dec1
  | None, None -> None
