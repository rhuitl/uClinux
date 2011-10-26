# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# It was modified by H D Moore to not crash the server during the test
#
#
# Supercedes MS01-033
#
#
# 
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10685);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0008");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0010");
 script_bugtraq_id(2690, 2880, 3190, 3193, 3194, 3195);
 script_cve_id( "CVE-2001-0544", 
 		"CVE-2001-0545", 
		"CVE-2001-0506", 
		"CVE-2001-0507", 
		"CVE-2001-0508",
		"CVE-2001-0500");
 script_version ("$Revision: 1.26 $");
 
 name["english"] = "IIS ISAPI Overflow";

 script_name(english:name["english"]);

 desc["english"] = "
There's a buffer overflow in the remote web server through
the ISAPI filter.
 
It is possible to overflow the remote web server and execute 
commands as user SYSTEM.

Additionally, other vulnerabilities exist in the remote web
server since it has not been patched.

Solution: See http://www.microsoft.com/technet/security/bulletin/ms01-044.mspx
Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Tests for a remote buffer overflow in IIS";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_ATTACK);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");

 # Family
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"],
               francais:family["francais"]);

 # Copyright
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");

 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port)) {
   
     
    req = string("GET /x.ida?", crap(length:220, data:"x"), "=x HTTP/1.1\r\n",
    	     "Host: ", get_host_name(), "\r\n\r\n");

    r = http_keepalive_send_recv(port:port, data:req);
    # 0xc0000005 == "Access Violation"
    if ("0xc0000005" >< r)
    {
        security_hole(port);
    }
}
