# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20414);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-04");
 script_cve_id("CVE-2005-4459");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-04
(VMware Workstation: Vulnerability in NAT networking)


    Tim Shelton discovered that vmnet-natd, the host module providing
    NAT-style networking for VMware guest operating systems, is unable to
    process incorrect \'EPRT\' and \'PORT\' FTP requests.
  
Impact

    Malicious guest operating systems using the NAT networking feature
    or local VMware Workstation users could exploit this vulnerability to
    execute arbitrary code on the host system with elevated privileges.
  
Workaround

    Disable the NAT service by following the instructions at http://www.vmware.com/support/k
    b, Answer ID 2002.
  
References:
    http://www.vmware.com/support/kb
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4459
    http://www.vmware.com/support/kb/enduser/std_adp.php?p_faqid=2000


Solution: 
    All VMware Workstation users should upgrade to a fixed version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-emulation/vmware-workstation
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-04] VMware Workstation: Vulnerability in NAT networking");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VMware Workstation: Vulnerability in NAT networking');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-emulation/vmware-workstation", unaffected: make_list("ge 5.5.1.19175", "rge 4.5.3.19414"), vulnerable: make_list("lt 5.5.1.19175")
)) { security_hole(0); exit(0); }
