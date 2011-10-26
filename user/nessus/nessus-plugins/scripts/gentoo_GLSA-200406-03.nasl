# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14514);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-03
(sitecopy: Multiple vulnerabilities in included libneon)


    Multiple format string vulnerabilities and a heap overflow vulnerability
    were discovered in the code of the neon library (GLSA 200405-01 and
    200405-13). Current versions of the sitecopy package include their own
    version of this library.
  
Impact

    When connected to a malicious WebDAV server, these vulnerabilities could
    allow execution of arbitrary code with the rights of the user running
    sitecopy.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of sitecopy.
  
References:
    http://www.gentoo.org/security/en/glsa/glsa-200405-01.xml
    http://www.gentoo.org/security/en/glsa/glsa-200405-13.xml


Solution: 
    All sitecopy users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-misc/sitecopy-0.13.4-r2"
    # emerge ">=net-misc/sitecopy-0.13.4-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-03] sitecopy: Multiple vulnerabilities in included libneon");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sitecopy: Multiple vulnerabilities in included libneon');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/sitecopy", unaffected: make_list("ge 0.13.4-r2"), vulnerable: make_list("le 0.13.4-r1")
)) { security_warning(0); exit(0); }
