#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18244);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-T-0014");
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2005-1476", "CVE-2005-1477");
 script_bugtraq_id(13544, 13641, 13645);

 name["english"] = "Mozilla Browser < 1.7.8";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A web browser installed on the remote host contains multiple
vulnerabilities. 

Description :

The remote version of Mozilla contains various security issues which
may allow an attacker to execute arbitrary code on the remote host. 

Solution : 

Upgrade to Mozilla 1.7.8 or later.

Risk factor : 

High / CVSS Base Score : 8
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_org_installed.nasl");
 exit(0);
}


ver = get_kb_item("Mozilla/Version");
if (!ver) exit(0);

ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (
    int(ver[0]) == 1 &&
    (
      int(ver[1]) < 7 ||
      (int(ver[1]) == 7 && int(ver[2]) < 8)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
