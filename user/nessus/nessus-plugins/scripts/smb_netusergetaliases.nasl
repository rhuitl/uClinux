#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10893);
 script_version("$Revision: 1.12 $");
 name["english"] = "Obtains the lists of users aliases";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to retrieve users aliases.

Description :

Using the supplied credentials it was possible to retrieve the
list of groups each user belong to.
Aliases are stored in the KB for further checks.

Risk factor :

None / CVSS Base Score : 0 
(AV:L/AC:H/Au:R/C:N/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Implements NetUserGetGroups()";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", 
		     "smb_sid2user.nasl",
		     "snmp_lanman_users.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/Users/enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#deprecated
exit(0);

include("smb_func.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

count = 1;
login = string(get_kb_item(string("SMB/Users/", count)));
while(login)
{
 groups = NetUserGetLocalGroups (user:login);

 foreach group (groups)
 {
  name = string("SMB/Users/", count, "/LocalGroups");
  set_kb_item(name:name, value:group);
 }	     

 count = count + 1;
 login = string(get_kb_item(string("SMB/Users/", count)));
}

NetUseDel ();
