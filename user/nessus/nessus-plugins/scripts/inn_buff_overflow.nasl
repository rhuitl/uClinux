#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPL v2

if(description)
{
 script_id(14683);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(1249);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"1353");
 script_cve_id("CVE-2000-0360");
 
 name["english"] = "INN buffer overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running INN (InterNetNews).

The remote version of this server does not do proper bounds checking. 
An attacker may exploit this issue to crash the remote service by overflowing
some of the buffers by sending a maliciously formatted news article.

Solution : Upgrade to version 2.2.2 of this service or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks INN version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

port = get_kb_item("Services/nntp");
if(!port) port = 119;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
  if(soc)
  {
    r = recv_line(socket:soc, length:1024);
    if ( r == NULL ) exit(0);
    #check for version 2.0.0 to 2.2.1
    if(egrep(string:r, pattern:"^20[0-9] .* INN 2\.(([0-1]\..*)|(2\.[0-1][^0-9])) .*$"))
    {
      security_hole(port);
    }
  }
}
