#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to retrieve users who can never changed their password
using the supplied credentials.

Description :

Using the supplied credentials it was possible to extract the list of
domain users who never changed their password.
It is recommended to allow/force users to change their password for
security reasons.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

if(description)
{
 script_id(10898);
 script_version("$Revision: 1.7 $");
 name["english"] = "Users information : Never changed password";

 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the users that have special privileges";

 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : User management";
 script_family(english:family["english"]);
 script_dependencies("smb_netusergetinfo.nasl");
 
 exit(0);
}
port = get_kb_item("SMB/transport");
if(!port)port = 139;


logins = "";
count = 1;
login = get_kb_item(string("SMB/Users/", count));
while(login)
{
 p = get_kb_item(string("SMB/Users/", count, "/Info/PassLastSet"));
 if(p)
 {
  nvr = "0x00-0x00-0x00-0x00-0x00-0x00-0x00-0x00";
  if(p == nvr){
  	logins = string(logins, login, "\n");
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/Users/", count));
}

if(logins)
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following users never changed their password :\n",
		logins);

 security_warning (port:0, data:report);
}
