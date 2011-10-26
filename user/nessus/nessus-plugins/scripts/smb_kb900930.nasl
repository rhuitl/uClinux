#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18680);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(14225);

 name["english"] = "Outlook Express Multiple Vulnerabilities (900930)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Denial of Service can be launched against Outlook Express client.

Description :

The remote host runs a version of Outlook Express which contains multiple 
vulnerabilities.

An attacker may exploit these vulnerabilities to disable the Outlook Express 
client of a victim.

To exploit this flaw, an attacker would need to send a malformed e-mail 
message to a victim and wait for him to read it using outlook.

Solution : 

Microsoft has released a set of patches for Windows XP :

Solution : http://support.microsoft.com/kb/900930/EN-US/

Risk factor : 

Low / CVSS Base Score : 2 
(AV:L/AC:H/Au:NR/C:N/A:P/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Microsoft Hotfix 900930";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms05-030.nasl");
 script_require_keys("SMB/OutlookExpress/MSOE.dll/Version");
 exit(0);
}


v = get_kb_item("SMB/OutlookExpress/MSOE.dll/Version");
if ( ! v ) exit(0);

vi = split(v, sep:".", keep:0);
if ( int(vi[0]) == 6 && int(vi[1]) == 0 && int(v[2]) < 3790 && int(v[2]) >= 2800 )
{
 if ( int(v[2]) < 2900 || (int(v[2]) == 2900 &&  int(v[3]) < 2670))
	security_note(port:get_kb_item("SMB/transport"));
}
