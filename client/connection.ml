open Lwt.Infix
open Websocket
open Command

let section = Lwt_log.Section.make "wsclient"

exception HTTP_Error of string

include Websocket.Make(Cohttp_lwt_unix.IO)

let http_error msg = Lwt.fail (HTTP_Error msg)
let protocol_error msg = Lwt.fail (Protocol_error msg)

let set_tcp_nodelay flow =
  let open Conduit_lwt_unix in
  match flow with
  | TCP { fd; _ } -> Lwt_unix.setsockopt fd Lwt_unix.TCP_NODELAY true
  | _ -> ()

let fail_unless eq f =
  if not eq then f () else Lwt.return_unit

let fail_if eq f =
  if eq then f () else Lwt.return_unit

(*
 * TODO:
 * Currently steal from the websocket source code
 * Later need to customize the ctx
 *)
let with_connection
    ?(extra_headers = Cohttp.Header.init ())
    ?(random_string=Websocket.Rng.init ())
    ?(ctx=Conduit_lwt_unix.default_ctx)
    client uri =
  let connect () =
    let module C = Cohttp in
    let nonce = Base64.encode_exn (random_string 16) in
    let headers = C.Header.add_list extra_headers
        ["Upgrade"               , "websocket";
         "Connection"            , "Upgrade";
         "Sec-WebSocket-Key"     , nonce;
         "Sec-WebSocket-Version" , "13"] in
    let req = C.Request.make ~headers uri in
    Conduit_lwt_unix.connect ~ctx client >>= fun (flow, ic, oc) ->
    set_tcp_nodelay flow;
    let drain_handshake () =
      Request.write (fun _writer -> Lwt.return ()) req oc >>= fun () ->
      Response.read ic >>= (function
        | `Ok r -> Lwt.return r
        | `Eof -> Lwt.fail End_of_file
        | `Invalid s -> Lwt.fail @@ Failure s) >>= fun response ->
      let status = C.Response.status response in
      let headers = C.Response.headers response in
      fail_if C.Code.(is_error @@ code_of_status status)
        (fun () -> http_error C.Code.(string_of_status status)) >>= fun () ->
      fail_unless (C.Response.version response = `HTTP_1_1)
        (fun () -> protocol_error "wrong http version") >>= fun () ->
      fail_unless (status = `Switching_protocols)
        (fun () -> protocol_error "wrong status") >>= fun () ->
      begin match C.Header.get headers "upgrade" with
      | Some a when String.lowercase_ascii a = "websocket" -> Lwt.return_unit
      | _ -> protocol_error "wrong upgrade"
      end >>= fun () ->
      fail_unless (upgrade_present headers)
        (fun () -> protocol_error "upgrade header not present") >>= fun () ->
      begin match C.Header.get headers "sec-websocket-accept" with
      | Some accept when accept = b64_encoded_sha1sum (nonce ^ websocket_uuid) -> Lwt.return_unit
      | _ -> protocol_error "wrong accept"
      end >>= fun () ->
      Lwt_log.info_f ~section "Connected to %s" (Uri.to_string uri)
    in
    Lwt.catch drain_handshake begin fun exn ->
      Lwt_io.close ic >>= fun () ->
      Lwt.fail exn
    end >>= fun () ->
    Lwt.return (ic, oc)
  in
  connect () >|= fun (ic, oc) ->
  let read_frame = make_read_frame ~mode:(Client random_string) ic oc in
  let read_frame () = Lwt.catch read_frame (fun exn -> Lwt.fail exn) in
  let buf = Buffer.create 128 in
  let write_frame frame =
    Buffer.clear buf;
    Lwt.wrap2
      (write_frame_to_buf ~mode:(Client random_string)) buf frame >>= fun () ->
    Lwt_io.write oc @@ Buffer.contents buf in
  read_frame, write_frame

type responce_handler = string -> unit Lwt.t 

let standard_react send handler fr
    : 'a option Lwt.t =
    let open Frame in
    let open Resolver_lwt_unix in
    let open Conduit_lwt_unix in
    match fr.opcode with
    | Opcode.Ping ->
      ignore @@ send @@ Frame.create ~opcode:Opcode.Pong ();
      Lwt.return None
    | Opcode.Pong -> Lwt.return None
    | Opcode.Close -> begin
      (* Immediately echo and pass this last message to the user *)
      let%lwt _ = (if String.length fr.content >= 2
          then
              send @@ Frame.create ~opcode:Opcode.Close
              ~content:(String.sub fr.content 0 2) ()
          else send @@ Frame.close 1000)
      in
      Lwt.fail Exit
      end
    | Opcode.Text
    | Opcode.Binary -> handler fr.content
    | _ ->
      let%lwt _ = Lwt_log.debug ~section
	"Warning. Client received unexcepted msg" in
      let%lwt _ = send @@ Frame.close 1002 in
      Lwt.fail Exit

(* Return the send, recv pair of a websocket
 * connection
 *)
let setup_connection uri =
  let open Frame in
  let open Resolver_lwt_unix in
  let open Conduit_lwt_unix in
  let%lwt endp = Resolver_lwt.resolve_uri ~uri
                 system in
  let%lwt client = endp_to_client ~ctx:default_ctx endp in
  with_connection ~ctx:default_ctx client uri

(*
 * Execute command through an extablished
 * websocket (sender, recv) pair.
 * 
 * The handler must be a pure function.
 *
 *)
let execute_command send recv cmd handler
  : 'a option Lwt.t =
  let react = standard_react send (fun content->
      let%lwt _ = Lwt_io.printf "> %s\n> %!" content in
      let%lwt result = Lwt.return @@ ResponseDecoder.get_response content in
      let%lwt _ = Lwt_io.printf "> Decoding:\n" in
      let%lwt _ = Lwt_io.printf "> Decoded Response:\n %s\n> %!" result
      in
      handler result
  ) in
  let content = JSONCommand.to_string cmd in
  Lwt_io.printf "> Sending\n %s\n" content >>= fun () ->
  send @@ Frame.create ~content () >>= fun () ->
  recv () >>= fun fr -> react fr

