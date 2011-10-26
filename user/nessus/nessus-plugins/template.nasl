#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(FIXME);
 script_cve_id(FIXME);
 script_bugtraq_id(FIXME);
 
 name["english"] = 
 name["francais"] = 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = 
 desc["francais"] = 
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = 
 summary["francais"] = 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = 
 family["francais"] = 
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("example1.nasl");
 
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
res = http_keepalive_send_recv(port:port, data:http_get(item:"/", port:port));
display(res);
