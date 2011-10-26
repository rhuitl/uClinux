#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to retrieve users who can not change their password
using the supplied credentials.

Description :

Using the supplied credentials it was possible to extract the list of
users who can not change their password.
It is recommended to allow/force users to change their password for
security reasons.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

if(description)
{
 script_id(10912);
 script_version("$Revision: 1.5 $");
 name["english"] = "Local users information : Can't change password";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the users that have special privileges";

 
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
 acb = get_kb_item(string("SMB/LocalUsers/", count, "/Info/ACB"));
 if(acb)
 {
  if(acb & 0x0800){
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
		"The following users can not change their password :\n",
		logins);

 security_warning (port:0, data:report);
}
