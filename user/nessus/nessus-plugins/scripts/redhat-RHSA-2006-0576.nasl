#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22111);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2933");

 name["english"] = "RHSA-2006-0576: kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdebase packages that resolve a security issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The kdebase packages provide the core applications for KDE, the K Desktop
  Environment.

  A flaw was found in KDE where the kdesktop_lock process sometimes
  failed to terminate properly. This issue could either block the user\'s
  ability to manually lock the desktop or prevent the screensaver to
  activate, both of which could have a security impact for users who rely on
  these functionalities.
  (CVE-2006-2933)

  Please note that this issue only affected Red Hat Enterprise Linux 3.

  All users of kdebase should upgrade to these updated packages, which
  contain a patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0576.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdebase packages";
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
if ( rpm_check( reference:"kdebase-3.1.3-5.11", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.1.3-5.11", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdebase-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-2933", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0576", value:TRUE);
