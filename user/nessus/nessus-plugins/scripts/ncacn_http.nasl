#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10761);
 script_version ("$Revision: 1.5 $");
 name["english"] = "Detect CIS ports";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the CIS ports by connecting to the server and
processing the buffer received.

CIS (COM+ Internet Services) are RPC over HTTP tunneling
and requires IIS to operate.
CIS ports shouldn't be visible on internet but only behind a firewall.

If you do not use this service, then disable it as it may become
a security threat in the future, if a vulnerability is discovered.

Solution:
Disable CIS with DCOMCNFG or protect CIS ports by a Firewall.
http://support.microsoft.com/support/kb/articles/Q282/2/61.ASP

For more information about CIS:
http://msdn.microsoft.com/library/en-us/dndcom/html/cis.asp

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect banner with ncacn_http";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ncacn_http");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ncacn_http");
if (!port)exit(0);

key = string("ncacn_http/banner/", port);
banner = get_kb_item(key);
if(banner)
{
 data = string("A CIS (COM+ Internet Services) server is listening on this port\nServer banner :\n", banner);
 security_note(port:port, data:data);
}
