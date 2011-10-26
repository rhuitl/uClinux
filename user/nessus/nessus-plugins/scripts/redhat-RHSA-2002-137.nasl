#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12311);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0638");

 name["english"] = "RHSA-2002-137: util";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  The util-linux package shipped with Red Hat Linux Advanced Server contains
  a locally exploitable vulnerability.

  The util-linux package contains a large variety of low-level system
  utilities that are necessary for a Linux system to function. The \'chfn\'
  utility included in this package allows users to modify personal
  information stored in the system-wide password file, /etc/passwd. In order
  to modify this file, this application is installed setuid root.

  Under certain conditions, a carefully crafted attack sequence can be
  performed to exploit a complex file locking and modification race present
  in this utility allowing changes to be made to /etc/passwd.

  In order to successfully exploit the vulnerability and perform privilege
  escalation there is a need for a minimal administrator interaction.
  Additionally, the password file must be over 4 kilobytes, and the local
  attackers entry must not be in the last 4 kilobytes of the password file.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2002-0638 to this issue.

  An interim workaround is to remove setuid flags from /usr/bin/chfn and
  /usr/bin/chsh. All users of Red Hat Linux should update to the errata
  util-linux packages which contain a patch to correct this vulnerability.

  Many thanks to Michal Zalewski of Bindview for alerting us to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-137.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the util packages";
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
if ( rpm_check( reference:"util-linux-2.11f-17.7.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"util-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0638", value:TRUE);
}

set_kb_item(name:"RHSA-2002-137", value:TRUE);
