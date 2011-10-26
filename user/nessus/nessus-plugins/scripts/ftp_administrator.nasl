#
# This script was written by Keith Young <Keith.Young@co.mo.md.us>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11160);
 script_version ("$Revision: 1.4 $");
 script_name(english:"Windows Administrator NULL FTP password");
	     

 script_description(english:"
The remote server is incorrectly configured 
with a NULL password for the user 'Administrator' and has 
FTP enabled. 
 
Solution : Change the Administrator password on this host.

Risk factor : High");
		 
script_summary(english:"Checks for a NULL Windows Administrator FTP password",
	       francais:"Translate");

 script_category(ACT_GATHER_INFO);

 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2002 Keith Young",
 		  francais:"Ce script est Copyright (C) 2002 Keith Young");
 
 script_dependencie("find_service.nes", "DDI_FTP_Any_User_Login.nasl");
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
 if(get_kb_item("ftp/" + port + "/AnyUser"))exit(0);
 
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"Administrator", pass:""))security_hole(port);
 }
}
