# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14452);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200403-01");
 script_cve_id("CVE-2004-0110");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-01
(Libxml2 URI Parsing Buffer Overflow Vulnerabilities)


    Yuuichi Teranishi discovered a flaw in libxml2 versions prior to 2.6.6.
    When the libxml2 library fetches a remote resource via FTP or HTTP, libxml2
    uses parsing routines that can overflow a buffer caused by improper bounds
    checking if they are passed a URL longer than 4096 bytes.
  
Impact

    If an attacker is able to exploit an application using libxml2 that parses
    remote resources, then this flaw could be used to execute arbitrary code.
  
Workaround

    No workaround is available; users are urged to upgrade libxml2 to 2.6.6.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0110


Solution: 
    All users are recommended to upgrade their libxml2 installation:
    # emerge sync
    # emerge -pv ">=dev-libs/libxml2-2.6.6"
    # emerge ">=dev-libs/libxml2-2.6.6"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-01] Libxml2 URI Parsing Buffer Overflow Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Libxml2 URI Parsing Buffer Overflow Vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-libs/libxml2", unaffected: make_list("ge 2.6.6"), vulnerable: make_list("lt 2.6.6")
)) { security_warning(0); exit(0); }
