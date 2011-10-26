#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20899);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0481");

 name["english"] = "RHSA-2006-0205: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libpng packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The libpng package contains a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A heap based buffer overflow bug was found in the way libpng strips alpha
  channels from a PNG image. An attacker could create a carefully crafted PNG
  image file in such a way that it could cause an application linked with
  libpng to crash or execute arbitrary code when the file is opened by a
  victim. The Common Vulnerabilities and Exposures project has assigned the
  name CVE-2006-0481 to this issue.

  Please note that the vunerable libpng function is only used by TeTeX and
  XEmacs on Red Hat Enterprise Linux 4.

  All users of libpng are advised to update to these updated packages which
  contain a backported patch that is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0205.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng packages";
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
if ( rpm_check( reference:"libpng-1.2.7-1.el4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.2.7-1.el4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libpng-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0481", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0205", value:TRUE);
