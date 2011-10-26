#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21593);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2003-1294", "CVE-2004-2655");

 name["english"] = "RHSA-2006-0498: xscreensaver";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated xscreensaver package that fixes two security flaws is now
  available for Red Hat Enterprise Linux 2.1 and 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  XScreenSaver is a collection of screensavers.

  A keyboard focus flaw was found in the way XScreenSaver prompts the user to
  enter their password to unlock the screen. XScreenSaver did not properly
  ensure it had proper keyboard focus, which could leak a users password to
  the program with keyboard focus. This behavior is not common, as only
  certain
  applications exhibit this focus error. (CVE-2004-2655)

  Several flaws were found in the way various XScreenSaver screensavers
  create temporary files. It may be possible for a local attacker to create a
  temporary file in way that could overwrite a different file to which the
  user
  running XScreenSaver has write permissions. (CVE-2003-1294)

  Users of XScreenSaver should upgrade to this updated package, which
  contains backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0498.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xscreensaver packages";
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
if ( rpm_check( reference:"xscreensaver-3.33-4.rhel21.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xscreensaver-4.10-20", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xscreensaver-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-1294", value:TRUE);
 set_kb_item(name:"CVE-2004-2655", value:TRUE);
}
if ( rpm_exists(rpm:"xscreensaver-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-1294", value:TRUE);
 set_kb_item(name:"CVE-2004-2655", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0498", value:TRUE);
