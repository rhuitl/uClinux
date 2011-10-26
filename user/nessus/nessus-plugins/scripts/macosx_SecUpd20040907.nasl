#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14676);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0017");
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(11140, 11139, 11138, 11137, 11136, 11135);
 script_cve_id("CVE-2004-0493", "CVE-2004-0488", "CVE-2004-0821", "CVE-2004-0822", "CVE-2004-0607", "CVE-2004-0523", "CVE-2004-0794", "CVE-2004-0823");  #"CVE-2004-0175", "CVE-2004-0824", "CVE-2004-0825", "CVE-2004-0426", "CVE-2004-0361"); #, "CAN2004-0720", "CVE-2004-0521", "CVE-2004-0183", "CVE-2004-0184");
 name["english"] = "Mac OS X Security Update 2004-09-07";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-09-07.

This security update fixes the following components :

- CoreFoundation
- IPSec
- Kerberos
- libpcap
- lukemftpd
- NetworkConfig
- OpenLDAP
- OpenSSH
- PPPDialer
- rsync
- Safari
- tcpdump



Solution : http://docs.info.apple.com/article.html?artnum=61798
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-09-07";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.4 and 10.3.5 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[45]\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-09-07", string:packages) ) security_hole(0);
}
