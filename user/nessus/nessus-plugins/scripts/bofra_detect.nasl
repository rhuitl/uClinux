#
# Bofra virus detection
#
# Author: Brian Smith-Sweeney (brian@smithsweeney.com)
# http://www.smithsweeney.com
#
# Created: 11/15/04
# Last Updated: 11/15/04
#
# See the Nessus Scripts License for details
#

if(description)
{
        script_id(15746);
        script_version ("$Revision: 1.5 $");
	script_cve_id("CVE-2004-1050");
	script_bugtraq_id(11515);
        name["english"] = "Bofra Virus Detection";
        desc["english"] = "
The remote host seems to have been infected with the Bofra virus or one of its 
variants, which infects machines via an Internet Explorer IFRAME exploit.  
It is very likely this system has been compromised.
 
Solution : Re-install the remote system.
See also :  http://securityresponse.symantec.com/avcenter/venc/data/w32.bofra.c@mm.html
Risk factor : Critical";
 
        summary["english"] = "Determines the presence of a Bofra virus infection resulting from an IFrame exploit";
        family["english"] = "Backdoors";
        script_name(english:name["english"]);
        script_description(english:desc["english"]);
        script_summary(english:summary["english"]);
        script_category(ACT_GATHER_INFO);
        script_copyright(english:"This script is Copyright (C) 2004 Brian Smith-Sweeney");
        script_family(english:family["english"]);
	script_dependencies('http_version.nasl');
	script_require_ports(1639);
        exit(0);
}
 
#
# User-defined variables
#
# This is where we saw Bofra; YMMV
port=1639;

#
# End user-defined variables; you should not have to touch anything below this
#

# Get the appropriate http functions
include("http_func.inc");
include("http_keepalive.inc");


if ( ! get_port_state ( port ) ) exit(0);

# Prep & send the http get request, quit if you get no answer
req = http_get(item:"/reactor",port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
hex_res=hexstr(res);
if ("3c0049004600520041004d00450020005300520043003d00660069006c0065003a002f002f00" >< hex_res )
	security_hole(port);
else {
	if (egrep(pattern:"<IFRAME SRC=file://",string:res)){
		security_hole(port);
	}
}
