type command_id = string

module JSONClosure = Map.Make(String)

module TypesDb = Map.Make(String)

(* The error type *)
exception CommandError of string 

module JSONCommand = struct
  module Json = Yojson.Basic

  type t = 
    | CMD of Json.t
    | CMD_INVALID

  let to_string t = match t with
    | CMD t -> Json.to_string t
    | CMD_INVALID ->
        raise @@ CommandError "Cannot translate invalid command into string"

  type arg =
    | STR of string
    | VAR of string
    | JSON of Json.t
    | SUBCMD of arg list

  type argtype =
    | TString
    | TInt
    | TBool
    | TJson of (string * argtype) list
    | TList of argtype list

  exception TypingError of (argtype * arg list) 

  (* TODO: Not implemented *)
  let type_check t node = node

  (* Read Args and Construct a json node *)
  let rec compose_cmd_node ctx typ args =
    let open Json in
    let parse_arg t arg = match arg with
      | VAR vname -> type_check t @@ JSONClosure.find vname ctx
      | JSON json -> type_check t json
      | SUBCMD cmd -> compose_cmd_node ctx t cmd
      | STR str -> type_check t @@ Yojson.Basic.from_string str
    in
    match typ with
    | TList typs ->
      let nodes = List.map2 (fun t arg ->
          parse_arg t arg
      ) typs args in
      `List nodes
    | TJson infos -> begin
      let nodes = List.map2 (fun (n,t) arg ->
        let node = parse_arg t arg in
        (n, node)
      ) infos args in
      `Assoc nodes
      end
    | _ -> begin (* TBool, TInt, TString *)
      match args with
        | [s] -> parse_arg typ s
        | _ -> raise @@ TypingError (typ, args)
      end

  let compose env method_name ctx args cid = 
    try
      let typeinfo = TypesDb.find method_name env in 
      let para = compose_cmd_node ctx typeinfo args in
      let cmd = `Assoc [
            ("jsonrpc", `String "2.0")
          ; ("method", `String method_name)
          ; ("para", para)
          ; ("id", `String cid)
      ] in
      CMD cmd
    with
    | Not_found -> raise @@ CommandError method_name
    | e -> raise e

  let compose_unsafe method_name args id =
      let cmd = [
            ("jsonrpc", `String "2.0")
          ; ("method", `String method_name)
          ; ("id", `Int id)
      ] in
      let cmd = match args with
      | None -> `Assoc cmd
      | Some args -> `Assoc (cmd @ ["para", args])
      in
      CMD cmd

    

end

(*
 * There is no good JDT implementation so far
 * We uses camlp5 to construct a dynamic parser based
 * on the Command Description File.
 * 
 * In substrate the Commands description file is
 * encoded in the metadata.
 *)

module ResponseDecoder = struct
  open Hex

  (*
   * After we decoded the meta from hex to string
   * we still need codec to decode the remaining stuff.
   * 
   * This is not good, which means the encoding of 
   * substrate rpc methods is binded with a non-standard
   * encoder.
   *)
  let decode hex_str =
    let s = hex_str in
    Hex.to_string s

  exception InvalidResponse of string

  (* We assume that the json result is always encoded *)
  let get_response str =
      let open Yojson.Basic in
      let json = from_string str in
      try
        let result = json |> Util.member "result" in
        match result with
        | `String s -> begin
            let s = String.sub s 2
                    (String.length s - 2) in
            decode @@ `Hex s
        end
        |  _ -> raise @@ InvalidResponse "result is a not string"
      with Not_found -> raise @@ InvalidResponse "result does not present in response"

  (*
   * TODO: Not implemented
   *)
  let verify cmd = true
end

module CommandDB = struct
  (* TODO change the following into functor *)
  module Out = Lwt_io

  type t = Yojson.Basic.t

  let query t = `Assoc [
      ("result", `String "unknown")
  ]

  let to_string t = Yojson.Basic.to_string t

  (*
   * TODO not implemented yet
   *)
  let compile db cmdjson = cmdjson

  let query_command db str :JSONCommand.t = 
    let cmdjson = query str in
    JSONCommand.CMD cmdjson

  (*
   * TODO not implemented yet
   *)
  let compose_command db cmdstream = 
    try
        let cmd = query_command db cmdstream in
        cmd
    with _ ->
        JSONCommand.CMD_INVALID

  (* TODO not implemented yet
   *)
  let create t = t
end

