 #
# (C) Tenable Network Security
#
	       
if(description)
{
 script_id(11804);
 script_bugtraq_id(8274, 8275, 8276);
 script_version ("$Revision: 1.12 $");
 name["english"] = "Cumulative Patch for MS SQL Server (815495)";
 script_name(english:name["english"]);
 
 script_cve_id("CVE-2003-0230", "CVE-2003-0231", "CVE-2003-0232");
	       
  
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through SQL service.

Description :

The remote Microsoft SQL server is vulnerable to several flaws :

- Named pipe hijacking
- Named Pipe Denial of Service
- SQL server buffer overrun

These flaws may allow a user to gain elevated privileges on this
host.

Solution : 

Microsoft has released a set of patches for MSSQL 7 and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms03-031.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);

 summary["english"] = "Microsoft's SQL Version Query";
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

path = hotfix_get_mssqldir();
if (!path)
  exit (0);

if (is_accessible_share ())
{
 if ( ( hotfix_check_fversion(path:path, file:"sqlrepss.dll", version:"2000.80.765.0", min_version:"2000.80.0.0") == HCF_OLDER ) ||
      ( hotfix_check_fversion(path:path, file:"ums.dll", version:"2000.33.25.0", min_version:"2000.33.0.0") == HCF_OLDER ) )
  security_hole(get_kb_item("SMB/transport"));

 hotfix_check_fversion_end();
}
