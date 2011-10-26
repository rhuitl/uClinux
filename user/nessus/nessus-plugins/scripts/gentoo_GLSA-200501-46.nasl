# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-46.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16437);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-46");
 script_cve_id("CVE-2005-0133");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-46
(ClamAV: Multiple issues)


    ClamAV fails to properly scan ZIP files with special headers
    (CVE-2005-0133) and base64 encoded images in URLs.
  
Impact

    By sending a base64 encoded image file in a URL an attacker could
    evade virus scanning. By sending a specially-crafted ZIP file an
    attacker could cause a Denial of Service by crashing the clamd daemon.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0133
    http://sourceforge.net/forum/forum.php?forum_id=440649
    http://secunia.com/advisories/13900/


Solution: 
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.81"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-46] ClamAV: Multiple issues");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple issues');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.81"), vulnerable: make_list("le 0.80")
)) { security_warning(0); exit(0); }
