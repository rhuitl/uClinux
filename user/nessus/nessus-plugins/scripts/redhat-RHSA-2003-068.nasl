#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12370);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1511");

 name["english"] = "RHSA-2003-068: vnc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated VNC packages are available to fix a weak cookie vulnerability.

  VNC is a tool for providing a remote graphical user interface.

  The VNC server acts as an X server, but the script for starting it
  generates an MIT X cookie (which is used for X authentication) without
  using a strong enough random number generator. This could allow an
  attacker to be able to more easily guess the authentication cookie.

  All users of VNC are advised to upgrade to these erratum packages, which
  contain a patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-068.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vnc packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"vnc-3.3.3r2-18.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-doc-3.3.3r2-18.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-server-3.3.3r2-18.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"vnc-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1511", value:TRUE);
}

set_kb_item(name:"RHSA-2003-068", value:TRUE);
