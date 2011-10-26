#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15633);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0409");

 name["english"] = "RHSA-2004-585: xchat";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated xchat package that fixes a stack buffer overflow in the SOCKSv5
  proxy code.

  X-Chat is a graphical IRC chat client for the X Window System.

  A stack buffer overflow has been fixed in the SOCKSv5 proxy code.
  An attacker could create a malicious SOCKSv5 proxy server in such a way
  that X-Chat would execute arbitrary code if a victim configured X-Chat to
  use the proxy. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0409 to this issue.

  Users of X-Chat should upgrade to this erratum package, which contains a
  backported security patch, and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-585.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xchat packages";
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
if ( rpm_check( reference:"xchat-1.8.9-1.21as.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-2.0.4-4.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"xchat-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0409", value:TRUE);
}
if ( rpm_exists(rpm:"xchat-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0409", value:TRUE);
}

set_kb_item(name:"RHSA-2004-585", value:TRUE);
