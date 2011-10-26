#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18635);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2096");

 name["english"] = "RHSA-2005-569: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Zlib packages that fix a buffer overflow are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Zlib is a general-purpose lossless data compression library which is used
  by many different programs.

  Tavis Ormandy discovered a buffer overflow affecting Zlib version 1.2 and
  above. An attacker could create a carefully crafted compressed stream that
  would cause an application to crash if the stream is opened by a user. As
  an example, an attacker could create a malicious PNG image file which would
  cause a web browser or mail viewer to crash if the image is viewed. The
  Common Vulnerabilities and Exposures project assigned the name
  CVE-2005-2096 to this issue.

  Please note that the versions of Zlib as shipped with Red Hat Enterprise
  Linux 2.1 and 3 are not vulnerable to this issue.

  All users should update to these erratum packages which contain a patch
  from Mark Adler which corrects this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-569.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zlib packages";
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
if ( rpm_check( reference:"zlib-1.2.1.2-1.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1.2-1.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"zlib-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2096", value:TRUE);
}

set_kb_item(name:"RHSA-2005-569", value:TRUE);
