#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12388);
 script_version ("$Revision: 1.4 $");
script_cve_id("CVE-2003-0244");
			
 name["english"] = "RHSA-2003-145: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a kernel which is vulnerable to a remote denial 
of service.  

The Linux kernel handles all the low-level functionality of the Operating
System.  This version of the kernel is vulnerable to a flaw wherein a remote
attacker can forge source IP addresses in such a way as to create a very
long routing hash chain.  An attacker, exploiting this flaw, would need
the ability to craft TCP/IP packets destined to (or through) the Linux kernel.
A successful attack would shut down the server.

Solution : http://rhn.redhat.com/errata/RHSA-2003-145.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
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

if ( rpm_check( reference:"kernel-2.4.18-e.31", yank:"e", prefix:"kernel-", release:"RHEL2.1") ) 
	security_hole(0);


