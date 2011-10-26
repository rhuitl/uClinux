#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18037);
 script_cve_id("CVE-2005-1078");
 script_bugtraq_id(13131);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "XAMPP Default FTP Account";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running XAMP, an Apache distribution designed for
easy installation and administration.

The remote host is running an FTP server which seems to be configured
by XAMPP, as the username and passwords 'nobody/xampp' allows one to
log into the remote server.

Solution : Modify the FTP password of the remote host .
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to log in via FTP as nobody/xampp";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');

port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( get_kb_item("ftp/" + port + "/AnyUser") ) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"nobody", pass:"xampp"))security_warning(port);
  close(soc);
 }
}
