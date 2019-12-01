open Lwt.Infix
open Websocket
open Connection
open Command


let init_command_db send recv : 'a option Lwt.t=
  let m = "state_getMetadata" in
  let cmd = JSONCommand.compose_unsafe m
        None 1 in

  execute_command send recv cmd (fun meta_data ->
    let%lwt _ = Lwt_io.printf
      "> initial meta data failed"
    in
    Lwt.return None
  )

let dummy_log fr = Lwt_io.printf "%s" fr

let zkp_client uri =
  let%lwt recv, send = setup_connection uri in

  let%lwt db = init_command_db send recv
  in

  let rec react_forever () = match db with
    | None -> begin
        let%lwt _ = Lwt_log.debug ~section
        "Exit on error." in
        send @@ Frame.close 1000
      end
    | Some db -> begin
        Lwt_io.(read_line_opt stdin) >>= function
        | None -> begin
            let%lwt _ = Lwt_log.debug ~section
	        "Got EOF. Sending a close frame." in
            send @@ Frame.close 1000
          end
        | Some cmd -> begin
            let cmd = CommandDB.compose_command
              (Option.get !db) cmd in
            execute_command send recv cmd
                (fun x -> Lwt.return @@ Some x)
            >>= handle_result
          end
      end

  and handle_result r = match r with
    | None -> begin
        let%lwt _ = Lwt_log.debug ~section
        "Exit on None response." in
        send @@ Frame.close 1000
      end
    | Some jobj -> react_forever ()
  
  in react_forever ()

let apply_loglevel = function
| 2 -> Lwt_log.(add_rule "*" Info)
| 3 -> Lwt_log.(add_rule "*" Debug)
| _ -> ()

let () =
  let reset = ref false in
  let uri = ref "" in
  let cmd = ref "" in
  let set_uri s = uri := s in
  let fetch_cmd s = cmd := s in
  let spec_args = Arg.align [
      "-loglevel", Arg.Int apply_loglevel, "1-3 Set loglevel";
      "-r", Arg.Set reset, " ZKP reset sign process";
      "-url", Arg.String set_uri, " ZKP reset sign process";
    ] in
  let usage_msg = "Usage: " ^ Sys.argv.(0) ^ " <options> uri\nOptions are:" in
  Arg.parse spec_args fetch_cmd usage_msg;
  Lwt_main.run (zkp_client (Uri.of_string !uri))
