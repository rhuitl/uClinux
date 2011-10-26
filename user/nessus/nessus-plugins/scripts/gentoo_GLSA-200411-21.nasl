# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15696);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-21");
 script_cve_id("CVE-2004-0930", "CVE-2004-0882");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-21
(Samba: Multiple vulnerabilities)


    Samba fails to do proper bounds checking when handling
    TRANSACT2_QFILEPATHINFO replies. Additionally an input validation flaw
    exists in ms_fnmatch.c when matching filenames that contain wildcards.
  
Impact

    An attacker may be able to execute arbitrary code with the permissions
    of the user running Samba. A remote attacker may also be able to cause
    an abnormal consumption of CPU resources, resulting in slower
    performance of the server or even a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.samba.org/samba/security/CAN-2004-0930.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0930
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0882
    http://security.e-matters.de/advisories/132004.html


Solution: 
    All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/samba-3.0.8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-21] Samba: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.8", "lt 3.0"), vulnerable: make_list("lt 3.0.8")
)) { security_warning(0); exit(0); }
