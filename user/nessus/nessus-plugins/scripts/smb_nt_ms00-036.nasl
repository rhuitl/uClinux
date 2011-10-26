#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10434);
 script_bugtraq_id(1262);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2000-0404");
 name["english"] = "NT ResetBrowser frame & HostAnnouncement flood patch";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to partially crash the remote host.

Description :

The hotfix for the 'ResetBrowser Frame' and the 'HostAnnouncement flood'
has not been applied.

The first of these vulnerabilities allows anyone to shut
down the network browser of this host at will.

The second vulnerability allows an attacker to
add thousands of bogus entries in the master browser,
which will consume most of the network bandwidth as
a side effect.

Solution :

http://www.microsoft.com/technet/security/bulletin/ms00-036.mspx

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q262694 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes.inc");


if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q262694") > 0 )
		security_warning(port);

