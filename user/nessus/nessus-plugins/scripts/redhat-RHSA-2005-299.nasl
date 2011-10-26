#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17590);
 script_version ("$Revision: 1.1 $");

 name["english"] = "RHSA-2005-299: realplayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated realplayer packages that fix a number of security issues are now
  available for Red Hat Enterprise Linux 3 Extras.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The realplayer package contains RealPlayer, a media format player.

  A number of security issues have been discovered in RealPlayer 8 of which a
  subset are believed to affect the Linux version as shipped with Red Hat
  Enterprise Linux 3 Extras. RealPlayer 8 is no longer supported by
  RealNetworks.

  Users of RealPlayer are advised to upgrade to this erratum package which
  contains RealPlayer 10.




Solution : http://rhn.redhat.com/errata/RHSA-2005-299.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the realplayer packages";
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
if ( rpm_check( reference:"realplayer-10.0.3-1.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}


set_kb_item(name:"RHSA-2005-299", value:TRUE);
