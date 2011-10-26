# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22108);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200607-10");
 script_cve_id("CVE-2006-3403");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200607-10
(Samba: Denial of Service vulnerability)


    During an internal audit the Samba team discovered that a flaw in the
    way Samba stores share connection requests could lead to a Denial of
    Service.
  
Impact

    By sending a large amount of share connection requests to a vulnerable
    Samba server, an attacker could cause a Denial of Service due to memory
    consumption.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3403


Solution: 
    All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/samba-3.0.22-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200607-10] Samba: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.22-r3"), vulnerable: make_list("lt 3.0.22-r3")
)) { security_warning(0); exit(0); }
