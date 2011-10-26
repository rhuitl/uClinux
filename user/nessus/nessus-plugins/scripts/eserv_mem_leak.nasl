#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
#
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# To: "BugTraq" <bugtraq@securityfocus.com>,
# Date: Sun, 11 May 2003 11:21:43 -0500
# Subject: [VulnWatch] eServ Memory Leak Enables Denial of Service Attacks


if(description)
{
 script_id(11619);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Eserv Memory Leaks";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Eserv HTTP/SMTP/FTP server.

There is a memory leak in this software which allows
any attacker to consumme all the available memory on
this host by making repeated requests to this service.

Solution : None at this time
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote host is running Eserv";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", "Services/smtp", "Services/ftp", 21, 25, 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("ftp_func.inc");
include("smtp_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(banner)
 {
  if(egrep(pattern:"^Server:.*Eserv/[0-2]", string:banner))
  {
   security_warning(port);
  }
 }
}

port = get_kb_item("Services/smtp");
if(!port) port = 25;
if(get_port_state(port))
{
 banner = get_smtp_banner(port:port);
 if(banner)
 {
  if(egrep(pattern:"^220*Eserv/[0-2]", string:banner))
  {
   security_warning(port);
  }
 }
}

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if(banner)
 {
  if(egrep(pattern:"^220*Eserv/[0-2]", string:banner))
  {
   security_warning(port);
  }
 }
}
