#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11683);
 script_bugtraq_id(7731, 7733, 7734, 7735);
 script_cve_id("CVE-2003-0224", "CVE-2003-0225", "CVE-2003-0226");

 script_version("$Revision: 1.13 $");
 name["english"] = "Cumulative Patch for Internet Information Services (Q11114)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote web server.

Description :

Cumulative Patch for Microsoft IIS (Q11114)

The remote host is running a version of IIS which is vulnerable to
various flaws which may allow remote attackers to disable this
service remotely and local attackers (or remote attackers with
the ability to upload arbitrary files on this server) to 
gain SYSTEM level access on this host.

Solution : 

Microsoft has released a set of patches for IIS 4.0, 5.0 and 5.1 :

http://www.microsoft.com/technet/security/bulletin/ms03-018.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if HF Q811114 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", file:"W3svc.dll", version:"5.1.2600.1166", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.0", file:"W3svc.dll", version:"5.0.2195.6672", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"4.0", file:"W3svc.dll", version:"4.2.785.1", dir:"\system32\inetsrv") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q811114") > 0  )
	security_hole(get_kb_item("SMB/transport"));

