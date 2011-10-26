#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11202);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-1999-0508");

 name["english"] = "Enhydra Multiserver Default Password";
 script_name(english:name["english"]);

 desc["english"] = "

This system appears to be running the Enhydra application
server configured with the default administrator password
of 'enhydra'. A potential intruder could reconfigure this 
service and use it to obtain full access to the system.

Solution: Please set a strong password of the 'admin' account.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Enhydra Multiserver Default Admin Password";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Digital Defense Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8001);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:8001);
if ( ! port ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner || "Enhydra" >!< banner ) exit(0);

if(get_port_state(port))
 {
   req = http_get(item:"/Admin.po?proceed=yes", port:port);
   req = req - string("\r\n\r\n");
   req = string(req, "\r\nAuthorization: Basic YWRtaW46ZW5oeWRyYQ==\r\n\r\n");
   buf = http_keepalive_send_recv(port:port, data:req);
  if("Enhydra Multiserver Administration" >< buf)
    {
        security_hole(port);
    }   
}
