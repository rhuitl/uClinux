#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10763);
 script_version ("$Revision: 1.5 $");
 name["english"] = "Detect the HTTP RPC endpoint mapper";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the http-rpc-epmap service by connecting
to the port 593 and processing the buffer received.

This endpoint mapper provides CIS (COM+ Internet Services)
parameters like port 135 (epmap) for RPC.

Solution:
Deny incoming traffic from the Internet to TCP port 593
as it may become a security threat in the future, if a
vulnerability is discovered.

For more information about CIS:
http://msdn.microsoft.com/library/en-us/dndcom/html/cis.asp

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect http-rpc-epmap";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/http-rpc-epmap", 593);
 exit(0);
}

#
# The script code starts here
#

exit(0); # Broken at this time

port = get_kb_item("Services/http-rpc-epmap");
if (!port) port = 593;
key = string("http-rpc-epmap/banner/", port);
banner = get_kb_item(key);

if(!banner)
{
if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
  {
  banner = recv(socket:soc, length:1000);
  close(soc);
  }
 }
}

if( "ncacn_http" >< banner)
{
 security_warning(port:port);
}
