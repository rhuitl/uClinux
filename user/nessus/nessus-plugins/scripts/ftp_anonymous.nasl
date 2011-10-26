#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#


desc["english"] = "
Synopsis :

Anonymous logins are allowed on the remote FTP server.

Description :

This FTP service allows anonymous logins. If you do not want to share data 
with anyone you do not know, then you should deactivate the anonymous account, 
since it can only cause troubles.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


if(description)
{
 script_id(10079);
 script_version ("$Revision: 1.37 $");
 script_cve_id("CVE-1999-0497");
 script_name(english:"Anonymous FTP enabled");
	     
 script_description(english:desc["english"]);
 
 script_summary(english:"Checks if the remote ftp server accepts anonymous logins");

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 script_dependencie("logins.nasl", "smtp_settings.nasl", 
	"ftpserver_detect_type_nd_version.nasl",
	"ftp_kibuv_worm.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/backdoor')) exit(0);

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 domain = get_kb_item("Settings/third_party_domain");
 r = ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", domain));
 if(r)
 {
  port2 = ftp_pasv(socket:soc);
  if(port2)
  {
   soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
   if (soc2)
   {
    send(socket:soc, data:'LIST\r\n');
    listing = ftp_recv_listing(socket:soc2);
    close(soc2);
    }
  }
  

  if(strlen(listing))
  {
   report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The content of the remote FTP root is :\n",
		listing);
  }
  else
    report = desc["english"];
 
 
  security_note(port:port, data:report);
  set_kb_item(name:"ftp/anonymous", value:TRUE);
  user_password = get_kb_item("ftp/password");
  if(!user_password)
  {
   set_kb_item(name:"ftp/login", value:"anonymous");
   set_kb_item(name:"ftp/password", value:string("nessus@", domain));
  }
 }
 close(soc);
}


