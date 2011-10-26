#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16296);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");

 name["english"] = "RHSA-2005-039: enscript";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated enscript package that fixes several security issues is now
  available.

  GNU enscript converts ASCII files to PostScript.

  Enscript has the ability to interpret special escape sequences. A flaw was
  found in the handling of the epsf command used to insert inline EPS files
  into a document. An attacker could create a carefully crafted ASCII file
  which made use of the epsf pipe command in such a way that it could execute
  arbitrary commands if the file was opened with enscript by a victim. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-1184 to this issue.

  Additional flaws in Enscript were also discovered which can only be
  triggered by executing enscript with carefully crafted command line
  arguments. These flaws therefore only have a security impact if enscript
  is executed by other programs and passed untrusted data from remote users.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CVE-2004-1185 and CVE-2004-1186 to these issues.

  All users of enscript should upgrade to these updated packages, which
  resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-039.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the enscript packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"enscript-1.6.1-16.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"enscript-1.6.1-24.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"enscript-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1184", value:TRUE);
 set_kb_item(name:"CVE-2004-1185", value:TRUE);
 set_kb_item(name:"CVE-2004-1186", value:TRUE);
}
if ( rpm_exists(rpm:"enscript-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1184", value:TRUE);
 set_kb_item(name:"CVE-2004-1185", value:TRUE);
 set_kb_item(name:"CVE-2004-1186", value:TRUE);
}

set_kb_item(name:"RHSA-2005-039", value:TRUE);
