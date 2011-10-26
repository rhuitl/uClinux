s/\(klips_debug:pfkey_msg_interp: parsing message type .. with msg_parser\) \(.........\)/\1 ABCDABCD/
s/\(klips_debug:pfkey_release: sock=\)\(........\)\( sk=\)\(........\)/\1ABCDABCD\3ABCDABCD/
s/\(klips_debug:pfkey_list_remove_socket: removing sock=\)\(........\)/\1ABCDABCD/
s/\(klips_debug:pfkey_create: sock=\)........\( type:. state:. flags:. protocol:.\)/\1ABCDABCD\2/
s/\(klips_debug:pfkey_create: sock->fasync_list=00000000 sk->sleep=\)........./\1ABCDABCD/
s/\(klips_debug:pfkey_list_insert_socket: socketp=\)......../\1ABCDABCD/
s/\(klips_debug:pfkey_create: Socket sock=\)........\( sk=\)........\( initialised.\)/\1ABCDABCD\2ABCDABCD\3/
s/pid=\([0-9]*\)\./pid=987./
s/\(klips_debug:pfkey_alloc_tdb: allocated tdb struct=\)........./\1ABDCABCD/
s/\(klips_debug:pfkey_alloc_ipsec_sa: allocated tdb struct=\)........./\1ABDCABCD/
s/\(klips_debug:pfkey_msg_interp: allocated extr->tdb=\)........./\1ABCDABCD/
s/\(klips_debug:pfkey_msg_parse: About to parse extension [0-9]* \)........\( with parser \)........./\1ABCDABCD\2ABCDABCD./
s/\(klips_debug:pfkey_msg_interp: processing ext [0-9]* \)........\( with processor \)........./\1ABCDABCD\2ABCDABCD/
s/\(klips_debug:pfkey_list_insert_socket: socketp=\)......../\1ABCDABCD/
s/\(klips_debug:pfkey_msg_interp: parsing message type [0-9]* with msg_parser \)........./\1ABCDABCD/
s/\(klips_debug:pfkey_msg_hdr_build: on_entry .pfkey_ext=\)........\( pfkey_ext=\)........\( .pfkey_ext=\)........./\1ABCDABCD\2ABCDABCD\3ABCDABCD/
s/\(klips_debug:pfkey_msg_build: pfkey_msg=\)........\( allocated [0-9]* bytes, &(extensions\[0\])=\)......../\1ABCDABCD\2ABCDABCD/
s/\(klips_debug:pfkey_msg_build: copying [0-9]* bytes from extensions\[[0-9]*\]=\)........\( to=\)......../\1ABCDABCD\2ABCDABCD/
s/\(klips_debug:pfkey_destroy_socket:\) .*/\1 STUFF/
s/\(klips_debug:pfkey_msg_hdr_build: on_exit .pfkey_ext=\)........\( pfkey_ext=\)........\( .pfkey_ext=\)........./\1ABCDABCD\2ABCDABCD\3ABCDABCD/
s/\(klips_debug:pfkey_insert_socket: sk=\)......../\1ABCDABCD/
s/\(klips_debug:pfkey_upmsg: ...allocated at \)........./\1ABCDABCD/
s/\(klips_debug:pfkey_.*_parse: sending up .* reply message for satype=.*(.*) to socket=\)........\( succeeded.\)/\1ABCDABCD\2/
s/\(pfkey_lib_debug:pfkey_msg_parse: About to parse extension .* 0x\)........\( with parser .*.\)/\1ABCDABCD\2/
s/\(klips_debug:pfkey_recvmsg: sock=\)........\( sk=\)........\( msg=\)........\( size=256.\)/\1ABCDABCD\2ABCDABCD\3ABCDABCD\4/
s/\(klips_debug:pfkey_alloc_eroute: allocated eroute struct=\)........./\1ABCDABCD/
s/\(klips_debug:pfkey_.*_parse: adding .*=\)......../\1ABCDABCD/
