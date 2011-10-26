#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# www.westpoint.ltd.uk
#
#
# See the Nessus Scripts License for details
#
# admins who installed this patch would necessarily not be vulnerable to CVE-2001-1325

if(description)
{
 script_id(10936);
 script_bugtraq_id(4476, 4483, 4486);
 script_version ("$Revision: 1.18 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0002");
 name["english"] = "IIS XSS via 404 error";
 name["francais"] = "IIS XSS via 404 error";
 script_name(english:name["english"], francais:name["francais"]);
 script_cve_id("CVE-2002-0148", "CVE-2002-0150");     # lots of bugs rolled into one patch...
 
 desc["english"] = "This IIS Server appears to vulnerable to one of the cross site scripting
attacks described in MS02-018. The default '404' file returned by IIS uses scripting to output a link to 
top level domain part of the url requested. By crafting a particular URL it is possible to insert arbitrary script into the
page for execution.

The presence of this vulnerability also indicates that you are vulnerable to the other issues identified in MS02-018 (various remote buffer overflow and cross site scripting attacks...)

References:
http://www.microsoft.com/technet/security/bulletin/MS02-018.mspx
http://jscript.dk/adv/TL001/

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for IIS XSS via 404 errors";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check makes a request for non-existent HTML file. The server should return a 404 for this request.
# The unpatched server returns a page containing the buggy JavaScript, on a patched server this has been
# updated to further check the input...

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/blah.htm", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( ! r ) exit(0);
 str1="urlresult";
 str2="+ displayresult +";

 if((str1 >< r) && (str2 >< r)) security_warning(port);
}
