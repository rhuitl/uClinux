#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17365);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0667");

 name["english"] = "RHSA-2005-303: sylpheed";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated sylpheed package that fixes a buffer overflow issue is now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Sylpheed is a GTK+ based fast email client.

  A buffer overflow bug has been found in the way Sylpheed handles non-ASCII
  characters in the header of a message to which a victim replies. A
  carefully crafted email message could potentially allow an attacker to
  execute arbitrary code on a victim\'s machine if they reply to such a
  message. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2005-0667 to this issue.

  Users of Sylpheed should upgrade to this updated package, which contains a
  backported patch, and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-303.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sylpheed packages";
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
if ( rpm_check( reference:"sylpheed-0.5.0-3.EL21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sylpheed-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0667", value:TRUE);
}

set_kb_item(name:"RHSA-2005-303", value:TRUE);
