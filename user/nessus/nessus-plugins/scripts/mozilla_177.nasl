#
# (C) Tenable Network Security
#


if(description)
{
 script_id(18065);
 script_version("$Revision: 1.6 $");

 script_bugtraq_id(13211, 13216, 13229, 13230, 13232, 13233);
 if ( NASL_LEVEL >= 2200 ) 
   script_cve_id(
     "CVE-2005-0989",
     "CVE-2005-1153",
     "CVE-2005-1154",
     "CVE-2005-1155",
     "CVE-2005-1156",
     "CVE-2005-1157",
     "CVE-2005-1159",
     "CVE-2005-1160"
   );
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"15690");
 }

 name["english"] = "Mozilla Browser < 1.7.7";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A web browser installed on the remote host contains multiple
vulnerabilities. 

Description :

The remote version of Mozilla contains various security issues which
may allow an attacker to execute arbitrary code on the remote host. 

See also :

http://www.mozilla.org/security/announce/mfsa2005-33.html
http://www.mozilla.org/security/announce/mfsa2005-35.html
http://www.mozilla.org/security/announce/mfsa2005-36.html
http://www.mozilla.org/security/announce/mfsa2005-37.html
http://www.mozilla.org/security/announce/mfsa2005-38.html
http://www.mozilla.org/security/announce/mfsa2005-40.html
http://www.mozilla.org/security/announce/mfsa2005-41.html

Solution : 

Upgrade to Mozilla 1.7.7 or later.

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
 script_require_keys("Mozilla/Version");

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
      (int(ver[1]) == 7 && int(ver[2]) < 7)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
