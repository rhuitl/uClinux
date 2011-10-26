#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20858);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");

 name["english"] = "RHSA-2006-0200: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated firefox package that fixes several security bugs is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Igor Bukanov discovered a bug in the way Firefox\'s Javascript interpreter
  derefernces objects. If a user visits a malicious web page, Firefox could
  crash or execute arbitrary code as the user running Firefox. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2006-0292 to
  this issue.

  moz_bug_r_a4 discovered a bug in Firefox\'s XULDocument.persist() function.
  A malicious web page could inject arbitrary RDF data into a user\'s
  localstore.rdf file, which can cause Firefox to execute arbitrary
  javascript when a user runs Firefox. (CVE-2006-0296)

  A denial of service bug was found in the way Firefox saves history
  information. If a user visits a web page with a very long title, it is
  possible Firefox will crash or take a very long time the next time it is
  run. (CVE-2005-4134)

  This update also fixes a bug when using XSLT to transform documents.
  Passing DOM Nodes as parameters to functions expecting an xsl:param could
  cause Firefox to throw an exception.

  Users of Firefox are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0200.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the firefox packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"firefox-1.0.7-1.4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"firefox-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-4134", value:TRUE);
 set_kb_item(name:"CVE-2006-0292", value:TRUE);
 set_kb_item(name:"CVE-2006-0296", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0200", value:TRUE);
