# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14479);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200404-14");
 script_cve_id("CVE-2004-0179");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-14
(Multiple format string vulnerabilities in cadaver)


    Cadaver code includes the neon library, which in versions 0.24.4 and
    previous is vulnerable to multiple format string attacks. The latest
    version of cadaver uses version 0.24.5 of the neon library, which makes it
    immune to this vulnerability.
  
Impact

    When using cadaver to connect to an untrusted WebDAV server, this
    vulnerability can allow a malicious remote server to execute arbitrary code
    on the client with the rights of the user using cadaver.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
References:
    http://www.webdav.org/cadaver
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0179


Solution: 
    cadaver users should upgrade to version 0.22.1 or later:
    # emerge sync
    # emerge -pv ">=net-misc/cadaver-0.22.1"
    # emerge ">=net-misc/cadaver-0.22.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-14] Multiple format string vulnerabilities in cadaver");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple format string vulnerabilities in cadaver');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/cadaver", unaffected: make_list("ge 0.22.1"), vulnerable: make_list("lt 0.22.1")
)) { security_warning(0); exit(0); }
