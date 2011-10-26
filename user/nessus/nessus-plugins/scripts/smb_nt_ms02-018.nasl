#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10943);
 script_bugtraq_id(4006, 4474, 4476, 4478, 4490, 6069, 6070, 6071, 6072);
 script_cve_id("CVE-2002-0147", "CVE-2002-0149",
 	       "CVE-2002-0150", "CVE-2002-0224",
 	       "CVE-2002-0869", "CVE-2002-1182",
	       "CVE-2002-1180", "CVE-2002-1181");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0002");
 script_version("$Revision: 1.24 $");
 name["english"] = "Cumulative Patch for Internet Information Services (Q327696)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web server.

Description :

The remote version of Windows contains multiple flaws in the Internet
Information Service (IIS) like Heap Overflow, DoS, XSS which may allow
an attacker to execute arbitrary code on the remote host with the SYSTEM
privileges.

Solution : 

Microsoft has released a set of patches for IIS 4.0, 5.0, 5.1 :

http://www.microsoft.com/technet/security/bulletin/ms02-062.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether October 30, 2002 IIS Cumulative patches (Q327696) are installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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
if ( hotfix_check_sp(nt:7, win2k:3, xp:1 ) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"W3svc.dll", version:"5.1.2600.1125", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"5.0", file:"W3svc.dll", version:"5.0.2195.5995", dir:"\system32\inetsrv") ||
      hotfix_is_vulnerable (os:"4.0", file:"W3svc.dll", version:"4.2.780.1", dir:"\system32\inetsrv") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q811114") > 0 &&
          hotfix_missing(name:"Q327696") > 0  ) 
  security_hole(get_kb_item("SMB/transport"));
     

