#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19381);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1769", "CVE-2005-2095");

 name["english"] = "RHSA-2005-595:   squirrelmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated squirrelmail package that fixes two security issues is now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SquirrelMail is a standards-based webmail package written in PHP4.

  A bug was found in the way SquirrelMail handled the $_POST variable. A
  user\'s SquirrelMail preferences could be read or modified if the user is
  tricked into visiting a malicious URL. The Common Vulnerabilities and
  Exposures project assigned the name CVE-2005-2095 to this issue.

  Several cross-site scripting bugs were discovered in SquirrelMail. An
  attacker could inject arbitrary Javascript or HTML content into
  SquirrelMail pages by tricking a user into visiting a carefully crafted
  URL, or by sending them a carefully constructed HTML email message.
  (CVE-2005-1769)

  All users of SquirrelMail should upgrade to this updated package, which
  contains backported patches that resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-595.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   squirrelmail packages";
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
if ( rpm_check( reference:"squirrelmail-1.4.3a-10", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squirrelmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1769", value:TRUE);
 set_kb_item(name:"CVE-2005-2095", value:TRUE);
}

set_kb_item(name:"RHSA-2005-595", value:TRUE);
