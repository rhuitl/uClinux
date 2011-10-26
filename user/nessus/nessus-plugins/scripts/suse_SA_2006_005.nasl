#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:005
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20821);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:005: nfs-server";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:005 (nfs-server).


An remotely exploitable problem exists in the rpc.mountd service in
the user space NFS server package 'nfs-server'.

Insufficient buffer space supplied to the realpath() function
when processing mount requests can lead to a buffer overflow in
the rpc.mountd and allows remote attackers to execute code as the
root user.

Code execution is definitely possible if the attacker can create
symlinks on any of the file systems on the machine running rpc.mountd
(/tmp , /home/attacker or similar).
For attackers without filesystem access code execution is potentially
possible.

NOTE:
The 'nfs-server' package is obsolete and has been replaced by the
'nfs-utils' package (kernel NFS server) in all currently supported
SUSE Linux products already and is only included for completeness.
The 'nfs-utils' package itself is NOT affected by this problem.

This issue is tracked by the Mitre CVE ID CVE-2006-0043.


Solution : http://www.suse.de/security/advisories/2006_05_nfsserver.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the nfs-server package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"nfs-server-2.2beta51-212.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-server-2.2beta51-206.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-server-2.2beta51-208.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nfs-server-2.2beta51-209.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
