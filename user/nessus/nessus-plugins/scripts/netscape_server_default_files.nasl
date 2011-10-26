#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(12077);
  script_version ("$Revision: 1.3 $");
# script_bugtraq_id();
# script_cve_id("");

 name["english"] = "Netscape Enterprise Server default files ";
 script_name(english:name["english"]);
 
 desc["english"] = "
Netscape Enterprise Server has default files installed.
Default files were found on the Netscape Enterprise Server.

These files should be removed as they may help an attacker to guess the
exact version of the Netscape Server which is running on this host.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Netscape Enterprise Server default files ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 David Kyger");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = string("

Default installation files were found on the Netscape Enterprise Server
Solution: Remove default files from the web server. 

These files should be removed as they may help an attacker to guess the
exact version of the Netscape Server which is running on this host.

The following default files were found:");

port = get_http_port(default:80);


if(get_port_state(port))
 {
  pat1 = "Netscape Enterprise Server Administrator's Guide";
  pat2 = "Enterprise Edition Administrator's Guide";
  pat3 = "Netshare and Web Publisher User's Guide";

  fl[0] = "/help/contents.htm";
  fl[1] = "/manual/ag/contents.htm";

  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf) || (pat2 >< buf) || (pat3 >< buf)) {
     warning = warning + string("\n", fl[i]);
     flag = 1;
     }
    }

    if (flag > 0) { 
     warning += '\n\nRisk factor : Low';
     security_warning(port:port, data:warning);
    }
}
