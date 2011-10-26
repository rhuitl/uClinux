#
# (C) Tenable Network Security
#
if(description)
{
 script_id(13643);
 script_bugtraq_id(10711);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0215");
 name["english"] = "Cumulative Security Update for Outlook Express (823353)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

It is possible to crash the remote email client.

Description :

The remote host is missing a cumulative security update for Outlook Express
which fixes a denial of service vulnerability in the Outlook Express mail
client.

To exploit this vulnerability, an attacker would need to send a malformed
message to a victim on the remote host. The message will crash her version
of Outlook, thus preventing her from reading her e-mail.

Solution : 

Microsoft has released a set of patches for Outlook Express :

http://www.microsoft.com/technet/security/bulletin/ms04-018.mspx

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-018 over the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms05-030.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");

if ( get_kb_item("SMB/897715") ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);


version = get_kb_item ("SMB/OutlookExpress/MSOE.dll/Version");
if (!version)
  exit (0);

port = get_kb_item("SMB/transport");
if(!port) port = 139;

v = split (version, sep:".", keep:FALSE);
flag = 0;

if ( v[0] == 5 )
	{
	 if ( (v[0] == 5 && v[1] < 50) || 
	      (v[0] == 5 && v[1] == 50 && v[2] < 4942) ||
	      (v[0] == 5 && v[1] == 50 && v[2] == 4942 && v[3] < 400 ) ) { security_warning(port); flag ++; }
	}
else if ( v[0] == 6 )
	{
	 if ( ( v[0] == 6 && v[1] == 0 && v[2] < 2742) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 2742 && v[3] < 2600 ) ) { security_warning(port); flag ++; }

	 else if ( ( v[0] == 6 && v[1] == 0 && v[2] > 2742 && v[2] < 2800) ||
	           ( v[0] == 6 && v[1] == 0 && v[2] == 2800 && v[3] < 1437 ) ) { security_warning(port); flag ++; }

	 else if( ( v[0] == 6 && v[1] == 0 && v[2] > 2800 && v[2] < 3790 ) ||
	          ( v[0] == 6 && v[1] == 0 && v[2] == 3790 && v[3] < 181 ) ) { security_warning(port); flag ++; }
	}

if ( flag == 0)
  set_kb_item (name:"SMB/KB823353", value:TRUE);
