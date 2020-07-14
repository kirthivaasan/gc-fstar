module Spec.GC

open Lib.IntTypes
open Lib.RawIntTypes
open Lib.ByteSequence
open Lib.Sequence
open Lib.LoopCombinators
open Spec.AES

module List = FStar.List.Tot
module S = Lib.Sequence (* redundancy? already opened Lib.Sequence*)

let wire_v = AES128

(* Circuit constants *)
let width:nat = 2
let depth:nat = 2
let n:nat = op_Multiply width depth

type wirekey = block
type ciphertext  = block

let zero_block = List.Tot.map u8 [
  0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
  0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00
]

let another_block = List.Tot.map u8 [
  0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
  0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x01;
]

let one_block = List.Tot.map u8 [
  0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
  0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x01;
]

let zero_wirekey : wirekey = assert_norm(List.length zero_block = 16); of_list zero_block
let one_wirekey : wirekey = assert_norm(List.length one_block = 16); of_list one_block
let another_wirekey : wirekey = assert_norm(List.length another_block = 16); of_list another_block

(* Compare blocks, after declassiying them *)
val eq_wirekey : wirekey -> wirekey -> bool
let eq_wirekey a b =
  let a_decl = let al = to_list a in List.map u8_to_UInt8 al in
  let b_decl = let bl = to_list b in List.map u8_to_UInt8 bl in
  a_decl = b_decl

let comparison = assert(eq_wirekey another_wirekey one_wirekey); 0x00

val set_wirekey_lsb : wirekey -> wirekey (* Set lsb to 1 *)
let set_wirekey_lsb wk =
  let masked_lsb = wk.[15] |. (u8 0x01) in
  let wk = wk.[15] <- masked_lsb in
  wk

val clr_wirekey_lsb : wirekey -> wirekey (* Set lsb to 0 *)
let clr_wirekey_lsb wk =
  let masked_lsb = wk.[15] &. (u8 0xfe) in
  let wk = wk.[15] <- masked_lsb in
  wk

let zero_wirekey' = set_wirekey_lsb zero_wirekey

val get_last_block_byte : wirekey -> nat
let get_last_block_byte blk =
  uint_to_nat blk.[15]

(* Print last byte *)
let main =
  IO.print_any (get_last_block_byte zero_wirekey')
