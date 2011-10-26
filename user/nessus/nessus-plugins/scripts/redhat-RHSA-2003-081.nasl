#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12374);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0107");

 name["english"] = "RHSA-2003-081: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated zlib packages that fix a buffer overflow vulnerability are now
  available.

  Zlib is a general-purpose, patent-free, lossless data compression
  library that is used by many different programs.

  The function gzprintf within zlib, when called with a string longer than
  Z_PRINTF_BUFZISE (= 4096 bytes), can overflow without giving a warning.

  zlib-1.1.4 and earlier exhibit this behavior. There are no known exploits
  of the gzprintf overrun, and only a few programs, including rpm2html
  and gimp-print, are known to use the gzprintf function.

  The problem has been fixed by checking the length of the output string
  within gzprintf.




Solution : http://rhn.redhat.com/errata/RHSA-2003-081.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zlib packages";
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
if ( rpm_check( reference:"zlib-1.1.4-8.2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.1.4-8.2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"zlib-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0107", value:TRUE);
}

set_kb_item(name:"RHSA-2003-081", value:TRUE);
