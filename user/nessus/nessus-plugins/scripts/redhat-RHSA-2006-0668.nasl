#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22463);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4019");

 name["english"] = "RHSA-2006-0668:   squirrelmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A new squirrelmail package that fixes a security issue as well as several
  bugs is now available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SquirrelMail is a standards-based webmail package written in PHP.

  A dynamic variable evaluation flaw was found in SquirrelMail. Users who
  have an account on a SquirrelMail server and are logged in could use this
  flaw to overwrite variables which may allow them to read or write other
  users\' preferences or attachments. (CVE-2006-4019)

  Users of SquirrelMail should upgrade to this erratum package, which
  contains SquirrelMail 1.4.8 to correct this issue. This package also
  contains a number of additional patches to correct various bugs.

  Note: After installing this update, users are advised to restart their
  httpd
  service to ensure that the new version functions correctly.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0668.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   squirrelmail packages";
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
if ( rpm_check( reference:"  squirrelmail-1.4.8-2.el3.noarch.rpm      0f4921da7a788f633aa016f993a9a9b6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"  squirrelmail-1.4.8-2.el4.noarch.rpm      5a86f850038d3a2df211c29af5c9070c", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  squirrelmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-4019", value:TRUE);
}
if ( rpm_exists(rpm:"  squirrelmail-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4019", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0668", value:TRUE);
