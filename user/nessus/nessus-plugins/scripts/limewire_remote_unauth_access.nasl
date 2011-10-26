#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Kevin Walsh <kwalsh at cs.cornell.edu>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(17973);
 script_bugtraq_id(12802);
 script_cve_id("CVE-2005-0788", "CVE-2005-0789");
 script_version("$Revision: 1.2 $");

 name["english"] = "Lime Wire Multiple Remote Unauthorized Access";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host seems to be running Lime Wire, a P2P file sharing program.

This version is vulnerable to remote unauthorized access flaws.
An attacker can access to potentially sensitive files on the 
remote vulnerable host.

Solution: Upgrade at least to version 4.8
Risk factor: High";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for remote unauthorized access flaw in Lime Wire";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 script_require_ports(6346);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

if(!port)port = 6346;
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(egrep(pattern:"limewire", string:serv, icase:TRUE))
{
  req = http_get(item:"/gnutella/res/C:\Windows\win.ini", port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   if("[windows]" >< r)
   {
    security_hole(port);
    exit(0);
   }
  }
}
