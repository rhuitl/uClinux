#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10910);
 script_version("$Revision: 1.16 $");
 name["english"] = "Obtains local user information";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to retrieve local user information.

Description :

Using the supplied credentials it was possible to retrieve
information for each local user.
User information is stored in the KB for further checks.

Risk factor :

None / CVSS Base Score : 0 
(AV:L/AC:H/Au:R/C:N/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Implements NetUserGetInfo()";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : User management";
  
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", 
		     "smb_sid2localuser.nasl",
		     "smb_host2sid.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/LocalUsers/enumerated", "SMB/host_sid");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

# script compatibility
function _ExtractTime(buffer)
{
 return(string(      hex(ord(buffer[7])), "-",
                     hex(ord(buffer[6])), "-",
                     hex(ord(buffer[5])), "-",
                     hex(ord(buffer[4])), "-",
                     hex(ord(buffer[3])), "-",
                     hex(ord(buffer[2])), "-",
                     hex(ord(buffer[1])), "-",
                     hex(ord(buffer[0]))));
}

if ( get_kb_item("SMB/samba") ) exit(0);

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
login = string(get_kb_item(string("SMB/LocalUsers/", count)));
while(login)
{
 info = NetUserGetInfo (user:login);

 if (!isnull (info))
 {
  name = string("SMB/LocalUsers/", count, "/Info/LogonTime");
  set_kb_item(name:name, value:_ExtractTime(buffer:info[0]));

  name = string("SMB/LocalUsers/", count, "/Info/LogoffTime");
  set_kb_item(name:name, value:_ExtractTime(buffer:info[1]));

  name = string("SMB/LocalUsers/", count, "/Info/KickoffTime");
  set_kb_item(name:name, value:_ExtractTime(buffer:info[2]));

  name = string("SMB/LocalUsers/", count, "/Info/PassLastSet");
  set_kb_item(name:name, value:_ExtractTime(buffer:info[3]));

  name = string("SMB/LocalUsers/", count, "/Info/PassCanChange");
  set_kb_item(name:name, value:_ExtractTime(buffer:info[4]));

  name = string("SMB/LocalUsers/", count, "/Info/PassMustChange");
  set_kb_item(name:name, value:_ExtractTime(buffer:info[5]));

  name = string("SMB/LocalUsers/", count, "/Info/ACB");
  set_kb_item(name:name, value:int(info[6]));
 }	     

 count = count + 1;
 login = string(get_kb_item(string("SMB/LocalUsers/", count)));
}

NetUseDel ();
