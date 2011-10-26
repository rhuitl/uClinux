#TRUSTED 9e5ee64eb848333fdd07c1fc58bfe2316231dec6eb2c23ad9b8b926c6a60c2b7bb4ad7a915e2c7771885142592828db69ffe967d6c9c77fc91f752692ef48af29c8548c0726f16d773f73fd0fd517ff1ab5b1c77a76f5443b66f5694a21ed4f78e3ec847b6e8101f1121ab55717996c89460089182a8c8cecbbc5acade8112cfdd0b8a3bfc39a91524532f90c1aa84e6b83634371661973800105ab9f4923b6e725cbad4a25bc93751d2934b127f6156b40556ca73828bc148d53b094ea65a384da8e85e9d02b171ee48219e2eba6752ef24b39fa23db1bd15f85128b64b96a6dbe5c0963af8b6a5a590f60be24723a04d46b618ebaebe18251edff7c92aced83d075f0ad0c26d6c92cd11cd5276fb23668d2c34108e33658ea23218b7903cbf61eca963bbffc552f6aa75bbe6de25e914d91aee4d4d0dde21ebff0eef49335a74ab1b0b0d37bafdbc83143fc31183f9218913bf69755985bfd61a93ef27c78d74c1aeb5d890b5f1cc845c6901ea9cd9b1284f04dc03583f868e0eb875f3caca1071562def63aeb3cb43e03cfd0a72a0078719aa8ed39da245059c6690ee9bcf39b070684180c8da46bcaa89d5673375deb023aaa16b63013c83162a2ec1b5c8b7fce84144e2d7ceac21861365d89ef9e10f3fc381b5f0d09d4f450b1f71272f4b32a09df5733a38e381b63b3d705c64444aa0007c880c67f4e484a4c757adc4
# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# (C) 2005 Tenable Network Security

OPT_WILL 	= 0xfb;
OPT_WONT 	= 0xfc;
OPT_DO   	= 0xfd;
OPT_DONT 	= 0xfe;

OPT_SUBOPT 	= 0xfa;
OPT_ENDSUBOPT 	= 0xf0;

function get_telnet_banner(port)
{
  local_var sb, banner, soc;
  sb = string("telnet/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = open_sock_tcp(port);
  if(!soc) return (0);
  banner = telnet_negotiate(socket:soc);
  close(soc);
  if(strlen(banner)){
	if ( defined_func("replace_kb_item") )
		replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
	else
		set_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
	}
  return(banner);
}


function telnet_negotiate(socket)
{
 local_var opt, code, s, counter, counter2, buf, prev;

 counter = 0;

 while ( TRUE )
 {
  s   = recv(socket:socket, length:1, timeout:3);
  if ( !strlen(s) ) break;
  if ( ord(s[0]) != 0xff) buf += s;
  else {
   counter ++;
   s  = recv(socket:socket, length:2);

   if ( ord(s[0]) == OPT_DO ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   if ( ord(s[0]) == OPT_WILL ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
   if ( ord(s[0]) == OPT_SUBOPT )
	{
	 # The remote telnet server is autistic :/
	 prev = recv(socket:socket, length:1);
         counter2 = 0;
	 while ( ord(prev) != 0xff && ord(s[0]) != OPT_ENDSUBOPT )
	   {
	    prev = s;
 	    # No timeout - the answer is supposed to be cached
	    s    = recv(socket:socket, length:1, timeout:0);
	    if ( ! strlen(s) ) return buf;
	    counter2++;
	    if ( counter2 >= 100 ) return buf;
	   }
	}
  
   # Not necessary and may introduce endless loops
   #if ( ord(s[0]) == OPT_DONT ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   #if ( ord(s[0]) == OPT_WONT ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
  }
  if ( counter >= 100 || strlen(buf) >= 4096 ) break;
 }

 
 return buf;
}

function set_telnet_banner(port, banner)
{
  local_var sb;
  sb = string("telnet/banner/", port);
  if ( defined_func("replace_kb_item") )
	replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
  else
	set_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
}


# (C) Tenable Security

function recv_until(socket, pattern)
{
 local_var r, i, l, buf;
 i = 0; l = 0;

#debug_print('recv_until(pattern=', pattern, ')\n');
 while ( TRUE )
 {
  i ++;
  if ( i > 1024*1024 ) return NULL;
  r = recv(socket:socket, length:1);
  if ( strlen(r) == 0 ) break;
  if (r == '\0') continue;	# The shell sometimes sends back very dirty things
  l ++;
  buf += r;
  # Regex size is limited?
  if (l <= 256)
  {
   if ( egrep(pattern:pattern,string:buf) ) return buf;
  }
  else
  {
   if (egrep(pattern:pattern,string:substr(buf, l - 256))) return buf;
  }
 }
#dump(ddata: buf, dtitle: 'telnet');
#debug_print('recv_until(pattern=', pattern, ') = NULL !\n');
#dump(dtitle: 'telnet', ddata: buf);
 return NULL;
}
