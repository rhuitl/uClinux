#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15959);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2001-1413");

 name["english"] = "RHSA-2004-536: ncompress";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
                                                                               
  An updated ncompress package that fixes a buffer overflow and problem in     
  the handling of files larger than 2 GB is now available.                     
                                                                               
  The ncompress package contains the compress and uncompress file compression  
  and decompression utilities, which are compatible with the original UNIX     
  compress utility (.Z file extensions).                                       
                                                                               
  A bug in the way ncompress handles long filenames has been discovered.       
  ncompress versions 4.2.4 and earlier contain a stack based buffer overflow   
  when handling very long filenames. It is possible that an attacker could     
  execute arbitrary code on a victims machine by tricking the user into        
  decompressing a carefully crafted filename. The Common Vulnerabilities and   
  Exposures project (cve.mitre.org) has assigned the name CVE-2001-1413 to     
  this issue.                                                                  
                                                                               
  This updated ncompress package also fixes a problem in the handling of       
  files larger than 2 GB.                                                      
                                                                               
  All users of ncompress should upgrade to this updated package, which         
  contains fixes for these issues.                                             
                                                                               
                                                                               


Solution : http://rhn.redhat.com/errata/RHSA-2004-536.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ncompress packages";
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
if ( rpm_check( reference:"ncompress-4.2.4-37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ncompress-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2001-1413", value:TRUE);
}

set_kb_item(name:"RHSA-2004-536", value:TRUE);
