#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21915);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2842");

 name["english"] = "RHSA-2006-0547:   squirrelmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated squirrelmail package that fixes a local file disclosure flaw is
  now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SquirrelMail is a standards-based webmail package written in PHP4.

  A local file disclosure flaw was found in the way SquirrelMail loads
  plugins. In SquirrelMail 1.4.6 or earlier, if register_globals is on and
  magic_quotes_gpc is off, it became possible for an unauthenticated remote
  user to view the contents of arbitrary local files the web server has
  read-access to. This configuration is neither default nor safe, and
  configuring PHP with the register_globals set on is dangerous and not
  recommended. (CVE-2006-2842)

  Users of SquirrelMail should upgrade to this erratum package, which
  contains a backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0547.html
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
if ( rpm_check( reference:"  squirrelmail-1.4.6-7.el3.noarch.rpm      47b5a0299a8e709af48cc45e95c9591a", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  squirrelmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-2842", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0547", value:TRUE);
