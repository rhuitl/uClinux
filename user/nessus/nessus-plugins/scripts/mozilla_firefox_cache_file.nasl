#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14197);
 script_bugtraq_id(10709);
 script_cve_id("CVE-2004-0760");
 script_version("$Revision: 1.7 $");

 name["english"] = "Firefox Cache File";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Firefox, an alternative web browser.

The remote version of this software contains a security issue which may
allow an attacker to execute arbitrary code on this host.

The security vulnerability is due to the fact that Firefox stores cached
HTML documents with a known file name, and to the fact that it's possible
to force Firefox to open cached files as HTML documents by appending
a NULL byte after the file name.

An attacker may combine these two flaws to execute arbitrary code on the
remote host.

Solution : Upgrade to Firefox 0.9.2
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Firefox";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_org_installed.nasl");
 exit(0);
}




ver = get_kb_item("Mozilla/Firefox/Version");
if (!ver) exit(0);

ver = split(ver, sep:'.', keep:FALSE);
if (
  int(ver[0]) == 0 &&
  (
    int(ver[1]) < 9 ||
    (int(ver[1]) == 9 && int(ver[2]) < 2)
  )
) security_hole(get_kb_item("SMB/transport"));
