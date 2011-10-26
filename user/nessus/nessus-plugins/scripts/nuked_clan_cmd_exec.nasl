#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Ref:
# Message-ID: <20030222014450.22428.qmail@www.securityfocus.com>
# From: "Grégory" Le Bras <gregory.lebras@security-corp.org>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-006] XSS & Function
#
# We don't check for all the listed BIDs since no patch has
# ever been made (ie: vulnerable to one => vulnerable to all)


if(description)
{
 script_id(11282);
 script_cve_id("CVE-2003-1238");
 script_bugtraq_id(6697, 6699, 6700, 6916, 6917);
 script_version ("$Revision: 1.14 $");

 name["english"] = "Nuked-Klan function execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to execute arbitrary php functions on the remote
host by using a flaw in the 'Nuked Klan' package.

An attacker may use this flaw to leak information
about the remote system or even execute arbitrary commands.

In addition to this problem, this service is vulnerable to
various cross site scripting attacks.

Solution : contact the author for a patch
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Executes phpinfo()";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc, module)
{
 local_var	url, req, r, h;

 if (! loc && report_paranoia < 2) return;	# Might generate a FP

 url = strcat(loc, "/index.php?file=", module, "&op=phpinfo");
 req = http_get(item: url, port:port);	
 r = http_keepalive_send_recv(port:port, data:req);
 if (isnull(r)) exit(0);
 if("allow_call_time_pass_reference" >< r){
 	security_hole(port);
	if (get_port_transport(port) > NESSUS_ENCAPS_IP) h = 'https';
	else h = 'http';
	log_print('Vulnerable Nuke clan found at ', h, '://', get_host_ip(), ':', port, url, '\n');
	exit(0);
  }
}


dirs = make_list("/nuked-clan", "/clan-nic", "/klan", "/clan", cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir, module:"News");
 #check(loc:dir, module:"Team");
 #check(loc:dir, module:"Lien");
}
