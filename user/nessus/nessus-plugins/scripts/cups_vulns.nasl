#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# GNU Public Licence
#

#
# This script checks for CVE-2002-1368, but incidentally covers
# all the issues listed, as they were all corrected in the
# same package
#

if(description)
{
 script_id(11199);
 script_bugtraq_id(6475);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2002-1383", "CVE-2002-1384", "CVE-2002-1366", 
               "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369",
	       "CVE-2002-1372");
 if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:002");

	       
	       
 
 name["english"] = "Multiple vulnerabilities in CUPS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CUPS server seems vulnerable to various
flaws which allow a remote attacker to shut down this
server or even to remotely gain the privileges of the
'lp' user.

Solution : upgrade to CUPS-1.1.18
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes the remote CUPS server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",631);
 script_require_keys("www/cups");
 exit(0);
}

#

include("http_func.inc");
include("misc_func.inc");


function check(port)
{
 #
 # This attack is non-destructive.
 # A non-patched cups will reply nothing to :
 # POST /printers HTTP/1.1\r\nContent-length: -1\r\n\r\n" (and won't
 # crash until we add another \r\n at the end of the request), 
 # whereas a patched cups will immediately reply with a code 400
 #

 if(http_is_dead(port:port))return(0);
 banner = get_http_banner(port:port);
 if(!banner)return(0); # we need to make sure this is CUPS

 if(egrep(pattern:"^Server: .*CUPS/.*", string:banner))
 {
 soc = http_open_socket(port);
 if (! soc) return(0);
 req = string("POST /printers HTTP/1.1\r\nHost: ", get_host_name(), "\r\nAuthorization: Basic AAA\r\nContent-Length: -1\r\n\r\n");
 # Add a \r\n to the line above to make the remote server crash 
 
 send(socket:soc, data: req);
 r = http_recv(socket: soc);
 http_close_socket(soc);
 if(!strlen(r))security_hole(port);	# The server dumbly waits for our data
 }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:631);

foreach port (ports)
{
 check(port:port);
}
