#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16064); 
 script_cve_id("CVE-2004-1373");
 script_bugtraq_id(12096);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SHOUTcast Format String Attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SHOUTcast server.

The remote version of this software is vulnerable to a format string
attack which may let an attacker execute arbitrary code on the remote host
by sending a malformed request to it.

Solution : Upgrade to SHOUTcast 1.9.5 or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "SHOUTcast version check";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

req = 'GET /content/dsjkdjfljk.mp3 HTTP/1.0\r\n\r\n';
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8000);
foreach port (ports)
{
 if (get_port_state(port))
 {
  banner = http_keepalive_send_recv(port:port, data:req);
  if ( banner != NULL )
  {
  if (egrep(pattern:"SHOUTcast Distributed Network Audio Server.*v(0\.|1\.[0-8]\.|1\.9\.[0-4][^0-9])", string:banner) )
  {
   security_warning(port);
   exit(0);
  } 
  }
 }
}
