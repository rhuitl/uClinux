#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12409);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0459");

 name["english"] = "RHSA-2003-236: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  This erratum provides updated KDE packages that resolve a security issue in
  Konquerer.

  KDE is a graphical desktop environment for the X Window System.
  Konqueror is the file manager for the K Desktop Environment.

  George Staikos reported that Konqueror may inadvertently send
  authentication credentials to websites other than the intended website in
  clear text via the HTTP-referer header. This can occur when authentication
  credentials are passed as part of a URL in the form http://
  user:password@host/

  Users of Konqueror are advised to upgrade to these erratum packages, which
  contain a backported security patch correcting this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-236.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts packages";
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
if ( rpm_check( reference:"arts-2.2.2-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0459", value:TRUE);
}

set_kb_item(name:"RHSA-2003-236", value:TRUE);
