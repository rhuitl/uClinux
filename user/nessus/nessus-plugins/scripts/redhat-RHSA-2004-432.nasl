#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14380);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0630", "CVE-2004-0631");

 name["english"] = "RHSA-2004-432: acroread";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated Adobe Acrobat Reader package that fixes multiple security issues
  is now available.

  The Adobe Acrobat Reader browser allows for the viewing, distributing, and
  printing of documents in portable document format (PDF).

  iDEFENSE has reported that Adobe Acrobat Reader 5.0 contains a buffer
  overflow when decoding uuencoded documents. An attacker could execute
  arbitrary code on a victim\'s machine if a user opens a specially crafted
  uuencoded document. This issue poses the threat of remote execution, since
  Acrobat Reader may be the default handler for PDF files. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2004-0631
  to this issue.

  iDEFENSE also reported that Adobe Acrobat Reader 5.0 contains an input
  validation error in its uuencoding feature. An attacker could create a
  file with a specially crafted file name which could lead to arbitrary
  command execution on a victim\'s machine. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2004-0630 to this issue.

  All users of Acrobat Reader are advised to upgrade to this updated package,
  which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-432.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the acroread packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"acroread-5.09-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-5.09-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"acroread-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0630", value:TRUE);
 set_kb_item(name:"CVE-2004-0631", value:TRUE);
}

set_kb_item(name:"RHSA-2004-432", value:TRUE);
