#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22442);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4334", "CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");

 name["english"] = "RHSA-2006-0667: gzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated gzip packages that fix several security issues are now available
  for Red Hat Enterprise Linux.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gzip package contains the GNU gzip data compression program.

  Tavis Ormandy of the Google Security Team discovered two denial of service
  flaws in the way gzip expanded archive files. If a victim expanded a
  specially crafted archive, it could cause the gzip executable to hang or
  crash. (CVE-2006-4334, CVE-2006-4338)

  Tavis Ormandy of the Google Security Team discovered several code execution
  flaws in the way gzip expanded archive files. If a victim expanded a
  specially crafted archive, it could cause the gzip executable to crash or
  execute arbitrary code. (CVE-2006-4335, CVE-2006-4336, CVE-2006-4337)

  Users of gzip should upgrade to these updated packages, which contain a
  backported patch and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0667.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gzip packages";
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
if ( rpm_check( reference:"gzip-1.3-19.rhel2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.3.3-13.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gzip-1.3.3-16.rhel4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gzip-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-4334", value:TRUE);
 set_kb_item(name:"CVE-2006-4335", value:TRUE);
 set_kb_item(name:"CVE-2006-4336", value:TRUE);
 set_kb_item(name:"CVE-2006-4337", value:TRUE);
 set_kb_item(name:"CVE-2006-4338", value:TRUE);
}
if ( rpm_exists(rpm:"gzip-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-4334", value:TRUE);
 set_kb_item(name:"CVE-2006-4335", value:TRUE);
 set_kb_item(name:"CVE-2006-4336", value:TRUE);
 set_kb_item(name:"CVE-2006-4337", value:TRUE);
 set_kb_item(name:"CVE-2006-4338", value:TRUE);
}
if ( rpm_exists(rpm:"gzip-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4334", value:TRUE);
 set_kb_item(name:"CVE-2006-4335", value:TRUE);
 set_kb_item(name:"CVE-2006-4336", value:TRUE);
 set_kb_item(name:"CVE-2006-4337", value:TRUE);
 set_kb_item(name:"CVE-2006-4338", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0667", value:TRUE);
