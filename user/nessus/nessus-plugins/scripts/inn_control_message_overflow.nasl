#
# (C) Tenable Network Security
#
# Ref: http://www.isc.org/products/INN/

if(description)
{
 script_id(11984);
 script_cve_id("CVE-2004-0045");
 script_bugtraq_id(9382);
 script_version ("$Revision: 1.4 $");
 name["english"] = "INN Control Message overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running INN 2.4.0.

There is a known security flaw in this version of INN which may allow an 
attacker to execute arbitrary code on this server.

See also : http://www.isc.org/products/INN/
Solution : upgrade to version 2.4.1
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks INN version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
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
    if(ereg(string:r, pattern:"^20[0-9] .* INN 2\.4\.0 .*$"))
    {
      security_hole(port);
    }
  }
}
