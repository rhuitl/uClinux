#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12405);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0252");

 name["english"] = "RHSA-2003-207: nfs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated nfs-utils packages are available that fix a remotely exploitable
  Denial of Service vulnerability.

  The nfs-utils package provides a daemon for the kernel NFS server and
  related tools.

  Janusz Niewiadomski found a buffer overflow bug in nfs-utils version 1.0.3
  and earlier. This bug could be exploited by an attacker, causing a remote
  Denial of Service (crash). It is not believed that this bug could lead to
  remote arbitrary code execution.

  Users are advised to update to these erratum packages, which contain a
  backported security patch supplied by the nfs-utils maintainers and are not
  vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-207.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nfs packages";
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
if ( rpm_check( reference:"nfs-utils-0.3.3-7.21AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"nfs-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0252", value:TRUE);
}

set_kb_item(name:"RHSA-2003-207", value:TRUE);
