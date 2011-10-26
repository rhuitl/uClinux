#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12320);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0391");

 name["english"] = "RHSA-2002-173: krb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Kerberos 5 packages are now available for Red Hat LInux Advanced
  Server. These updates fix a buffer overflow in the XDR decoder.

  Sun RPC is a remote procedure call framework which allows clients to invoke
  procedures in a server process over a network. XDR is a mechanism for
  encoding data structures for use with RPC.

  The Kerberos 5 network authentication system contains an RPC library which
  includes an XDR decoder derived from Sun\'s RPC implementation. The Sun
  implementation was recently demonstrated to be vulnerable to a heap
  overflow. It is believed that the attacker needs to be able to
  authenticate to the kadmin daemon for this attack to be successful. No
  exploits are known to currently exist.

  All users should upgrade to these errata packages which contain an updated
  version of Kerberos 5 which is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-173.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb packages";
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
if ( rpm_check( reference:"krb5-devel-1.2.2-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-14", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"krb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0391", value:TRUE);
}

set_kb_item(name:"RHSA-2002-173", value:TRUE);
