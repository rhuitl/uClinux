#
# (C) Tenable Network Security
#
#
# Requested by Michael Richardson
#

 desc["english"] = "
Synopsis :

It is possible to retrieve password policy using the supplied credentials.

Description :

Using the supplied credentials it was possible to extract the password
policy.
Password policy must be conform to the Informationnal System Policy.

Risk factor :

None / CVSS Base Score : 0 
(AV:L/AC:H/Au:R/C:N/A:N/I:N/B:N)";


if(description)
{
 script_id(17651);
 script_version("$Revision: 1.5 $");
 name["english"] = "Obtains the password policy";

 script_name(english:name["english"]);
 script_description(english:desc["english"]);
 
 summary["english"] = "Check password policy";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}

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

modals = NetUserGetModals(level:1);
if (!isnull(modals))
{
 policy = string("The following password policy is defined on the remote host:\n\n");
 policy += string("Minimum password len: ", modals[0], "\n");
 policy += string("Password history len: ", modals[1], "\n");
 if ( modals[2] < 0 )
 	policy += string("Maximum password age (d): No limit\n");
 else
 	policy += string("Maximum password age (d): ", modals[3]/(3600*24), "\n");

 if ( modals[3] == 0)
        policy += string("Password must meet complexity requirements: Disabled\n");
 else
        policy += string("Password must meet complexity requirements: Enabled\n");

 policy += string("Minimum password age (d): ", modals[4]/(3600*24), "\n");

 if ( modals[5] < 0 )
 	policy += string("Forced logoff time (s): Not set\n");
 else
 	policy += string("Forced logoff time (s): ", modals[5], "\n");

 modals2 = NetUserGetModals (level:3);
 if (!isnull (modals2))
 {
  if ( modals2[0] < 0 )
  	policy += string("Locked account time (s): Not set\n");
  else
  	policy += string("Locked account time (s): ", modals2[0], "\n");

  if ( modals2[1] < 0 )
  	policy += string("Time between failed logon (s): Not set\n");
  else
  	policy += string("Time between failed logon (s): ", modals2[1], "\n");

  policy += string("Number of invalid logon before locked out (s): ", modals2[2], "\n");
 }

 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		policy);

 security_note (port:port, data:report);
}

NetUseDel();
