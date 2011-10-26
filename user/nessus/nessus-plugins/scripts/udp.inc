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
# UDP
#


# Define a UDP structure
udp_sizes = make_array(
		"uh_sport", 16,
		"uh_dport", 16,
		"uh_ulen",  16,
		"uh_sum",   16);

udp_struct = make_list(
		"uh_sport",
		"uh_dport",
		"uh_ulen",
		"uh_sum");


function udp_checksum(udp, ip, payload)
{
 local_var src, dst, pseudo, udp_r, ret;

 if ( ip["type"] != "ip" || udp["type"] != "udp" )
	{
	display("udp_checksum: Bad IP argument\n");
	return NULL;
	}
 ip  = ip["data"];

 
 udp_r = mkudp(udp);
 
 src = ipaddr(ip["ip_src"]);
 dst = ipaddr(ip["ip_dst"]);
 pseudo = src +
	  dst +
	  mkbyte(0) +
	  mkbyte(IPPROTO_UDP) +
	  mkword(strlen(udp_r) + strlen(payload)) + udp_r + payload;

 ret = inet_sum(pseudo);
 return ret;
}

function udp_get(udp, element)
{
 if ( isnull(udp) || udp["type"] != "udp" )
	{
	display("udp_get: Invalid packet\n");
	return NULL;
	}

 udp = udp["data"];
 return udp[element];
}

function udp_set(udp, uh_sport, uh_dport, uh_ulen, uh_sum)
{
 local_var ret;
 if ( isnull(udp) || udp["type"] != "udp" )
 {
  display("udp_set: Bad packet type\n");
  return NULL;
 }

 udp = udp["data"];
 if ( !isnull(uh_sport) ) udp["uh_sport"] = uh_sport;
 if ( !isnull(uh_dport) ) udp["uh_dport"] = uh_dport;
 if ( !isnull(uh_ulen) ) udp["uh_ulen"] = uh_ulen;
 if ( !isnull(uh_sum) ) udp["uh_sum"] = uh_sum;


 ret["type"] = "udp";
 ret["data"] = udp;
 return ret;
}


function mkudp()
{
 local_var item, ret, n, b, udp;

 udp = _FCT_ANON_ARGS[0];
 
 if ( udp["type"] != "udp") 
 {
   display("mkudp : Bad packet type - ", udp["type"], "\n");
 } 

 udp = udp["data"];

 foreach item ( udp_struct )
 {
     if ( udp_sizes[item] == 16 ) ret += mkword(udp[item]);
     else {
	display("Inconsistent UDP structure\n");
	return NULL;
	}
 }

 return ret;
}


function udp(uh_sport, uh_dport, uh_ulen, uh_sum)
{
 local_var empty;
 if ( isnull(uh_sport) ) uh_sport = 1024;
 if ( isnull(uh_dport) ) uh_dport = 53;
 if ( isnull(uh_ulen ) ) uh_ulen  = 8;
 if ( isnull(uh_sum  ) ) uh_sum   = 0;

 empty["type"] = "udp";
 empty["data"] = NULL;
 return udp_set(udp:empty,
		uh_sport:uh_sport,
		uh_dport:uh_dport,
		uh_ulen: uh_ulen,
		uh_sum : uh_sum);
}
