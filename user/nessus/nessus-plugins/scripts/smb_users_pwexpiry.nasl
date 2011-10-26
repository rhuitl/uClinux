#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to retrieve users whose password never expires using 
the supplied credentials.

Description :

Using the supplied credentials it was possible to extract the list of
domain users whose password never expires.
It is recommended to allow/force users to change their password for
security reasons.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

if(description)
{
 script_id(10900);
 script_version("$Revision: 1.6 $");
 name["english"] = "Users information : Passwords never expires";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Lists the users that never logged in";

 
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
 p = get_kb_item(string("SMB/Users/", count, "/Info/PassMustChange"));
 if(p)
 {
  exp = "0x7f-0xff-0xff-0xff-0xff-0xff-0xff-0xff";
  if(p == exp){
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
		"The following users have password which never expires :\n",
		logins);

 security_warning (port:0, data:report);
}
