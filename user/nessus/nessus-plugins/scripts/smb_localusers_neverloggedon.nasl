#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to retrieve users who never logged in using the supplied
credentials.

Description :

Using the supplied credentials it was possible to extract the list of
local users who never logged into the remote host.
It is recommended to delete useless accounts.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if(description)
{
 script_id(10915);
 script_version("$Revision: 1.4 $");
 name["english"] = "Local users information : User has never logged on";

 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the local users that never logged in";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
family["english"] = "Windows : User management";
  
 script_family(english:family["english"]);
script_dependencies("smb_netusergetinfo_local.nasl");
 
 exit(0);
}


port = get_kb_item("SMB/transport");
if(!port)port = 139;

logins = "";
count = 1;
login = get_kb_item(string("SMB/LocalUsers/", count));
while(login)
{
 p = get_kb_item(string("SMB/LocalUsers/", count, "/Info/LogonTime"));
 if(p)
 { 
  exp = "0x00-0x00-0x00-0x00-0x00-0x00-0x00-0x00";
  if(p == exp){
  	logins = string(logins, login, "\n");
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/LocalUsers/", count));
}

if(logins)
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following users never logged in :\n",
		logins);

 security_warning (port:0, data:report);
}
