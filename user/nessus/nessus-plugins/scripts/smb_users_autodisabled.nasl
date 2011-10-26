#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

It is possible to retrieve disabled users account using the supplied
credentials.

Description :

Using the supplied credentials it was possible to extract the disabled
domain user account list.
This user accounts may have been disabled for security reasons or du
to brute force attacks attempts.

Risk factor :

None / CVSS Base Score : 0 
(AV:L/AC:H/Au:R/C:N/A:N/I:N/B:N)";


if(description)
{
 script_id(10895);
 script_version("$Revision: 1.5 $");
 name["english"] = "Users information : automatically disabled accounts";

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
 acb = get_kb_item(string("SMB/Users/", count, "/Info/ACB"));
 if(acb)
 {
  if(acb & 0x0400){
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
		"The following accounts are disabled :\n",
		logins);

 security_note (port:0, data:report);
}
