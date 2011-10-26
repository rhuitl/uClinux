#
# 
# (C) 2006 Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
#


#-------------------------------------------------------------------------#
# TCP                                                                     #
#-------------------------------------------------------------------------#

tcp_sizes = make_array(
		"th_sport",	16,
		"th_dport", 	16,
		"th_seq",	32,
		"th_ack",	32,
		"th_off",	 4,
		"th_x2",	 4,
		"th_flags",	 8,
		"th_win",	16,
		"th_sum",	16,
		"th_urp",	16);

tcp_struct = make_list(
		"th_sport",
		"th_dport",
		"th_seq",
		"th_ack",
		"th_off",
		"th_x2",
		"th_flags",
		"th_win",
		"th_sum",
		"th_urp",
		"options");


function tcp_checksum(tcp, ip, payload)
{
 local_var src, dst, pseudo, tcp_r;

 if ( ip["type"] != "ip" || tcp["type"] != "tcp" )
	{
	display("tcp_checksum: Bad IP argument\n");
	return NULL;
	}
 ip = ip["data"];
 src = ipaddr(ip["ip_src"]);
 dst = ipaddr(ip["ip_dst"]);
 tcp_r = mktcp(tcp);
 pseudo = src +
	  dst +
	  mkbyte(0) +
	  mkbyte(IPPROTO_TCP) +
	  mkword(strlen(tcp_r) + strlen(payload)) + tcp_r + payload;

 return inet_sum(pseudo);
}


function tcp_set(tcp, th_sport, th_dport, th_seq, th_ack, th_off, th_x2, th_flags, th_win, th_sum, th_urp )
{
 local_var head, tail, ret, t;

 if ( isnull(tcp) )
 {
  display("set_tcp: NULL TCP packet\n");
  return NULL;
 }

 if ( tcp["type"] != "tcp" )
  {
	display("set_tcp: bad packet type\n");
	return tcp;
	}

 tcp = tcp["data"];

 if ( ! isnull(th_sport) ) tcp["th_sport"] = th_sport;
 if ( ! isnull(th_dport) ) tcp["th_dport"] = th_dport;
 if ( ! isnull(th_seq)   ) tcp["th_seq"]   = th_seq;
 if ( ! isnull(th_ack)   ) tcp["th_ack"]   = th_ack;
 if ( ! isnull(th_off)   ) tcp["th_off"]   = th_off;
 if ( ! isnull(th_x2)    ) tcp["th_x2"]    = th_x2;
 if ( ! isnull(th_flags) ) tcp["th_flags"] = th_flags;
 if ( ! isnull(th_win) )   tcp["th_win"]   = th_win;
 if ( ! isnull(th_sum) )   tcp["th_sum"]   = th_sum;
 if ( ! isnull(th_urp) )   tcp["th_urp"]   = th_urp;

 ret["type"] = "tcp";
 ret["data"] = tcp;

 return ret;
}


function tcp(th_sport, th_dport, th_seq, th_ack, th_off, th_x2, th_flags, th_win, th_sum, th_urp )
{
 local_var empty;
 if ( isnull(th_sport) ) th_sport = rand() % ( 65535  - 1024 ) + 1024;
 if ( isnull(th_dport) ) th_dport = 80;
 if ( isnull(th_seq) ) th_seq = rand();
 if ( isnull(th_ack) ) th_ack = 0;
 if ( isnull(th_off) ) th_off = 5;
 if ( isnull(th_x2) )  th_x2  = 0;
 if ( isnull(th_flags))th_flags = TH_SYN;
 if ( isnull(th_win) ) th_win  = 65535;
 if ( isnull(th_urp) ) th_urp  = 0;

 empty["type"] = "tcp";
 empty["data"] = NULL;
 
 return tcp_set(tcp:empty,
	 	th_sport:th_sport,
		th_dport:th_dport,
		th_seq:th_seq,
		th_ack:th_ack,
		th_off:th_off,
		th_x2:th_x2,
		th_flags:th_flags,
		th_win:th_win,
		th_sum:th_sum,
		th_urp:th_urp);
}


function tcp_get(tcp, element)
{
 if ( isnull(tcp) || tcp["type"] != "tcp") 
 {
  display("tcp_get: Bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 tcp = tcp["data"];
 return tcp[element];
}

function mktcp()
{
 local_var tcp, ret, item,n,b;

 tcp = _FCT_ANON_ARGS[0];
 if ( tcp["type"] != "tcp" )
 {
  display("mktcp(): Bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 tcp = tcp["data"];
 foreach item ( tcp_struct )
 {
  if ( tcp_sizes[item] == 4 ) 
  {
	if ( n == 0 )
	{
	  b = tcp[item];
	  n = 1;
	}
	else 
	{
	  b = b << 4 | tcp[item];
	  ret += mkbyte(b);
	  n = 0;
	}
  }
  else if ( tcp_sizes[item] == 8 )  ret += mkbyte(tcp[item]);
  else if ( tcp_sizes[item] == 16 ) ret += mkword(tcp[item]);
  else if ( tcp_sizes[item] == 32 ) ret += mkdword(tcp[item]);
  else if ( item == "options" )
	{
	  if ( strlen(tcp[item]) % 4 ) tcp[item] += crap(data:mkbyte(0), length:4 - ( strlen(tcp[item]) % 4 ) );
	  ret += tcp[item];
	}
 }
 return ret;
}


function tcp_insert_option(tcp, type, length, data)
{
 local_var pkt;
 if ( isnull(tcp) || tcp["type"] != "tcp" ) 
 { 
  display("tcp_insert_option: bad packet type - ", tcp["type"], "\n");
  return NULL;
 }
 
 pkt = tcp["data"];
 pkt["options"] += mkbyte(type);
 if ( ! isnull(length) )
 { 
  pkt["options"] += mkbyte(length);
  pkt["options"] += data;
 }

 tcp["data"] = pkt;
 return tcp;
}


function tcp_finish_insert_option(tcp)
{
 local_var pkt;
 if ( isnull(tcp) || tcp["type"] != "tcp" ) 
 { 
  display("tcp_finish_insert_option: bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 pkt = tcp["data"];
 if ( strlen(pkt["options"]) % 4 )
	pkt["options"] += crap(length:4 - (strlen(pkt["options"]) % 4 ), data:mkbyte(0));

 pkt["th_off"] = 5 + (strlen(pkt["options"]) / 4);
 tcp["data"] = pkt;
 return tcp;
}

