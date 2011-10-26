#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21362);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1550");

 name["english"] = "RHSA-2006-0280: dia";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated Dia package that fixes several buffer overflow bugs are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Dia drawing program is designed to draw various types of diagrams.

  infamous41md discovered three buffer overflow bugs in Dia\'s xfig file
  format importer. If an attacker is able to trick a Dia user into opening a
  carefully crafted xfig file, it may be possible to execute arbitrary code
  as the user running Dia. (CVE-2006-1550)

  Users of Dia should update to these erratum packages, which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0280.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dia packages";
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
if ( rpm_check( reference:"dia-0.88.1-3.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dia-0.94-5.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"dia-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-1550", value:TRUE);
}
if ( rpm_exists(rpm:"dia-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-1550", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0280", value:TRUE);
