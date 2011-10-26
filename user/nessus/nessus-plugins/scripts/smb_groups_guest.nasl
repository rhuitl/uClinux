#
# (C) Tenable Network Security
#


if(description)
{
 script_id(10907);
 script_version("$Revision: 1.7 $");
 name["english"] = "Guest belongs to a group";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The Guest account have too much privileges.

Description :

Using the supplied credentials it was possible to determine that
the guest user belongs to groups other than guest users or domain
guests.
As guest should not have any privilege, you should fix this.

Solution :

Edit local or domain policy to restict guest account.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the groups of guest";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
 script_dependencies("smb_sid2user.nasl", "smb_sid2localuser.nasl");
 script_require_ports (139,445);
 exit(0);
}

include ("smb_func.inc");

guest_dom = get_kb_item ("SMB/Users/2");
guest_host = get_kb_item ("SMB/LocalUsers/2");

name	= kb_smb_name();
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

if (guest_host)
  aliases = NetUserGetLocalGroups (user:guest_host);

if (guest_dom)
  groups = NetUserGetGroups (user:guest_dom);

NetUseDel();

if(!isnull(groups))
{
 foreach group ( groups )
 {
  if ( group != 514 && group != 513 )
  {
   security_warning(0);
   exit(0);
  }
 } 
}

if(!isnull(aliases))
{
 foreach alias ( aliases )
 {
  if ( alias != 546 ) 
  {
   security_warning(0);
   exit(0);
  }
 }
}
