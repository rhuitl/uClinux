#
# This script was written by Renaud Deraison
#
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: 15 Apr 2003 00:34:13 -0000
#  From: denote <denote@freemail.com.au>
#  To: bugtraq@securityfocus.com
#  Subject: nb1300 router - default settings expose password
#

if(description)
{
 script_id(11539);
 script_bugtraq_id(7359);
 script_version ("$Revision: 1.5 $");
 script_name(english:"NB1300 router default FTP account");
	     

 script_description(english:"
It is possible to log into the remote FTP server with the
username 'admin' and the password 'password'.

If the remote host is a NB1300 router, this would allow an attacker
to steal the WAN credentials of the user, or even to reconfigure his
router remotely.
 
Solution : Change the admin password on this host.
Risk factor : High");
		 
script_summary(english:"Checks for admin/password");

 script_category(ACT_GATHER_INFO);

 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 
 script_dependencie("ftpserver_detect_type_nd_version.nasl", 
	"ftp_kibuv_worm.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#
include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
 if (get_kb_item("ftp/" + port + "/AnyUser") || get_kb_item('ftp/'+port+'/backdoor')) exit(0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"admin", pass:"password"))security_hole(port);
 }
}
