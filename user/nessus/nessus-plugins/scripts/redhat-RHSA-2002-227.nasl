#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12330);
 script_version ("$Revision: 1.3 $");

 name["english"] = "RHSA-2002-227: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  This kernel update for Red Hat Linux Advanced Server 2.1 addresses some
  security issues and provides minor bug fixes.

  The Linux kernel handles the basic functions of the operating system. A
  number of vulnerabilities were found in the Red Hat Linux Advanced Server
  kernel. These vulnerabilities could allow a local user to obtain elevated
  (root) privileges.

  The vulnerabilities existed in a number of drivers, including
  stradis, rio500, se401, apm, usbserial, and usbvideo.

  Additionally, a number of bugs have been fixed, and some small feature
  enhancements have been added.

  - Failed READA requests could be interpreted as I/O errors under high
  load on SMP; this has been fixed.

  - In rare cases, TLB entries could be corrupted on SMP Pentium IV
  systems; this potential for corruption has been fixed. Third-party modules
  will need to be recompiled to take advantage of these fixes.

  - The latest tg3 driver fixes have been included; the tg3 driver
  now supports more hardware.

  - A mechanism is provided to specify the location of core files and to
  set the name pattern to include the UID, program, hostname, and PID of
  the process that caused the core dump.

  A number of SCSI fixes have also been included:

  - Configure sparse LUNs in the qla2200 driver
  - Clean up erroneous accounting data as seen by /proc/partitions and iostat
  - Allow up to 128 scsi disks
  - Do not start logical units that require manual intervention, avoiding
  unnecessary startup delays
  - Improve SCSI layer throughput by properly clustering DMA requests

  All users of Red Hat Linux Advanced Server are advised to upgrade to the
  errata packages.




Solution : http://rhn.redhat.com/errata/RHSA-2002-227.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel packages";
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
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}


set_kb_item(name:"RHSA-2002-227", value:TRUE);
