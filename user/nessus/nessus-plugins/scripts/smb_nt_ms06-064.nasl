#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22537);
 script_version("$Revision: 1.1 $");
 #script_bugtraq_id();
 script_cve_id("CVE-2004-0790","CVE-2004-0230","CVE-2005-0688");

 name["english"] = "Vulnerability in TCP/IP IPv6 Could Allow Denial of Service (922819)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote host due to a flaw in the TCP/IP IPv6 
stack.

Description :

The remote host runs a version of Windows which has a flaw in its TCP/IP
IPv6 stack.

The flaw may allow an attacker to perform a denial of service attack
against the remote host.

To exploit this vulnerability, an attacker needs to send a specially crafted
ICMP or TCP packet to the remote host.

Solution : 

Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-064.mspx

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for 922819";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Tcpip6.sys", version:"5.2.3790.576", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Tcpip6.sys", version:"5.2.3790.2771", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Tcpip6.sys", version:"5.1.2600.1886", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Tcpip6.sys", version:"5.1.2600.2975", dir:"\system32\drivers") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( ( hotfix_missing(name:"922819") > 0 ) )
   security_warning(get_kb_item("SMB/transport"));
}
