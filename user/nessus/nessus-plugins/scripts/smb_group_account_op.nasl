#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to retrieve Users in the 'Account Operators' group
using the supplied credentials.

Description :

Using the supplied credentials it was possible to extract the member
list of group 'Account Operators'.
Members of this group can create or modify local user accounts but 
can not modify or create administrative accounts or edit user rights.

You should make sure that only the proper users are member of this
group.

Risk factor :

None / CVSS Base Score : 0 
(AV:L/AC:H/Au:R/C:N/A:N/I:N/B:N)";


if(description)
{
 script_id(10901);
 script_version("$Revision: 1.9 $");
 name["english"] = "Users in the 'Account Operator' group";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the users that are in special groups";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : User management";
 
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports (139,445);
 exit(0);
}

 
include ("smb_func.inc");

sid = raw_string (0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x24,0x02,0x00,0x00);

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

group = NULL;

lsa = LsaOpenPolicy (desired_access:0x20801);
if (!isnull(lsa))
{
 sids = NULL;
 sids[0] = sid;
 names = LsaLookupSid (handle:lsa, sid_array:sids);
 if (!isnull(names))
 {
  group = parse_lsalookupsid(data:names[0]);
 }
 
 LsaClose (handle:lsa);
}

if (isnull(group))
{
 NetUseDel();
 exit(0);
}

members = NetLocalGroupGetMembers (group:group[2]);

foreach member ( members )
{
  member = parse_lsalookupsid(data:member);
  report = report + string(". ", member[1], "\\", member[2], " (", SID_TYPE[member[0]], ")\n");
}

NetUseDel();

if( report )
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following users are in the 'Account Operators' group :\n",
		report);

 security_note(port:0, data:report);
}
