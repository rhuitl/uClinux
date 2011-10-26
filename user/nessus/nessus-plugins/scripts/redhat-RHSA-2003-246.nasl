#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12413);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0466");

 name["english"] = "RHSA-2003-246: wu";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated wu-ftpd packages are available that fix an off-by-one buffer
  overflow.

  The wu-ftpd package contains the Washington University FTP (File Transfer
  Protocol) server daemon. FTP is a method of transferring files between
  machines.

  An off-by-one bug has been discovered in versions of wu-ftpd up to and
  including 2.6.2. On a vulnerable system, a remote attacker would be able
  to exploit this bug to gain root privileges.

  Red Hat Enterprise Linux contains a version of wu-ftpd that is affected by
  this bug, although it is believed that this issue will not be remotely
  exploitable due to compiler padding of the buffer that is the target of the
  overflow. However, Red Hat still advises that all users of wu-ftpd upgrade
  to these erratum packages, which contain a security patch.

  Red Hat would like to thank Wojciech Purczynski and Janusz Niewiadomski of
  ISEC Security Research for their responsible disclosure of this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-246.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wu packages";
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
if ( rpm_check( reference:"wu-ftpd-2.6.1-21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"wu-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0466", value:TRUE);
}

set_kb_item(name:"RHSA-2003-246", value:TRUE);
