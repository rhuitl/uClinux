#
# (C) Tenable Network Security
#
if(description)
{
 script_id(18028);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2005-0048", "CVE-2004-0790", "CVE-2004-1060", "CVE-2004-0230", "CVE-2005-0688");
 script_bugtraq_id(13124, 13116);

 name["english"] = "Vulnerabilities in TCP/IP Could Allow Remote Code Execution (network check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
TCP/IP stack.

Description :

The remote host runs a version of Windows which has a flaw in its TCP/IP
stack.

The flaw may allow an attacker to execute arbitrary code with SYSTEM
privileges on the remote host, or to perform a denial of service attack
against the remote host.

Proof of concept code is available to perform a Denial of Service against
a vulnerable system.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-019.mspx

Risk factor : 
High / CVSS Base Score : 9 
(AV:R/AC:L/Au:NR/C:P/A:C/I:P/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Microsoft Hotfix KB893066 (network check)";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("tcp_seq_window.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
 script_require_keys("TCP/seq_window_flaw", "Host/OS/smb");
 exit(0);
}

include("global_settings.inc");
if ( report_paranoia < 2 ) exit(0);
os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows" >!< os || "Windows 4.0" >< os ) exit(0);

if (get_kb_item("TCP/seq_window_flaw"))
 security_hole(port:get_kb_item("SMB/transport"));
