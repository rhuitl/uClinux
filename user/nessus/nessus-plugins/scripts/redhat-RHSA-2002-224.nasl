#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12329);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1232");

 name["english"] = "RHSA-2002-224: ypserv";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ypserv packages which fix a memory leak are now available for Red
  Hat Linux Advanced Server.

  [Updated 08 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  ypserv is an NIS authentication server. ypserv versions before 2.5 contain
  a memory leak that can be triggered remotely.

  When someone requests a map that doesn\'t exist, a previous mapname may be
  leaked. This happens, for instance, if you run "ypmatch foo
  aaaaaaaaaaaaaaaaaaaa". Repeated runs will result in the yp server using
  more and more memory, and running more slowly. It could also result in
  ypserv being killed due to the system being out of memory.

  This errata updates Red Hat Advanced Server 2.1 to a patched version of
  ypserv that doesn\'t have the memory leak.




Solution : http://rhn.redhat.com/errata/RHSA-2002-224.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ypserv packages";
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
if ( rpm_check( reference:"ypserv-1.3.12-2.AS21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ypserv-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1232", value:TRUE);
}

set_kb_item(name:"RHSA-2002-224", value:TRUE);
