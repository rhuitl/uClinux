#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16053);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1036");

 name["english"] = "RHSA-2004-654:   squirrelmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated SquirrelMail package that fixes a cross-site scripting
  vulnerability is now available.

  SquirrelMail is a webmail package written in PHP.

  A cross-site scripting bug has been found in SquirrelMail. This issue
  could allow an attacker to send a mail with a carefully crafted header,
  which could result in causing the victim\'s machine to execute a malicious
  script. The Common Vulnerabilities and Exposures project has assigned the
  name CVE-2004-1036 to this issue.

  Additionally, the following issues have been addressed:

  - updated splash screens
  - HIGASHIYAMA Masato\'s patch to improve Japanese support
  - real 1.4.3a tarball
  - config_local.php and default_pref in /etc/squirrelmail/ to match upstream
  RPM.

  Please note that it is possible that upgrading to this package may remove
  your SquirrelMail configuration files due to a bug in the RPM package.
  Upgrading will prevent this from happening in the future.

  Users of SquirrelMail are advised to upgrade to this updated package which
  contains a patched version of SquirrelMail version 1.43a and is not
  vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-654.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   squirrelmail packages";
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
if ( rpm_check( reference:"squirrelmail-1.4.3a-7.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"  squirrelmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1036", value:TRUE);
}

set_kb_item(name:"RHSA-2004-654", value:TRUE);
