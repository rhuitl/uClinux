# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14559);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200408-03");
 script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-03
(libpng: Numerous vulnerabilities)


    libpng contains numerous vulnerabilities including null pointer dereference
    errors and boundary errors in various functions.
  
Impact

    An attacker could exploit these vulnerabilities to cause programs linked
    against the library to crash or execute arbitrary code with the permissions
    of the user running the vulnerable program, which could be the root user.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0597
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0598
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0599


Solution: 
    All libpng users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=media-libs/libpng-1.2.5-r8"
    # emerge ">=media-libs/libpng-1.2.5-r8"
    You should also run revdep-rebuild to rebuild any packages that depend on
    older versions of libpng :
    # revdep-rebuild
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-03] libpng: Numerous vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libpng: Numerous vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/libpng", unaffected: make_list("ge 1.2.5-r8"), vulnerable: make_list("le 1.2.5-r7")
)) { security_warning(0); exit(0); }
