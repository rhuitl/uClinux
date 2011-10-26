#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10603);
 script_bugtraq_id(2303);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0006");
 
 name["english"] =  "Winsock Mutex Vulnerability (Q279336)";
 name["francais"] = "Winsock Mutex Vulnerability (Q279336)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A bug in the remote operating system allows a local user to disable the network
functions of the remote host.

Description :

By default, Windows NT sets weak permissions on the Winsock mutex. A local user 
without any privilege may abuse these permissions to lock the mutex indefinitely 
and therefore disrupt the network operations of the remote host.

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms01-003.mspx

Risk factor :

Low / CVSS Base Score : 2 
(AV:L/AC:L/Au:NR/C:N/A:P/I:N/B:A)";




 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q279336 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 && hotfix_missing(name:"Q279336") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
