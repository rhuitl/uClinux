#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15860);
 script_bugtraq_id(11776);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "CuteFTP multiple flaws (2)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the program CuteFTP.exe installed.

CuteFTP is an FTP client which contains seversl overflow conditions
which may be exploited by an attacker to gain a shell on this
host.

To exploit these vulnerabilities, an attacker would need to set
up a rogue FTP server and lure a user of this host to browse it
using CuteFTP.

Solution : None at this time
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of CuteFTP.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("cuteftp_flaws.nasl");
 exit(0);
}


version = get_kb_item("SMB/Windows/Products/CuteFTP/Version");
if ( ! version ) exit(0);
if(ereg(pattern:"^([0-5]\.|6\.0\.0\.)", string:version))
  security_hole(port);
