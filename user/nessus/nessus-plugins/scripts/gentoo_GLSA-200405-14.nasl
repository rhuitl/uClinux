# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14500);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200405-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-14
(Buffer overflow in Subversion)


    All releases of Subversion prior to 1.0.3 have a vulnerability in the
    date-parsing code. This vulnerability may allow denial of service or
    arbitrary code execution as the Subversion user. Both the client and server
    are vulnerable, and write access is NOT required to the server\'s
    repository.
  
Impact

    All servers and clients are vulnerable. Specifically, clients that allow
    other users to write to administrative files in a working copy may be
    exploited. Additionally all servers (whether they are httpd/DAV or
    svnserve) are vulnerable. Write access to the server is not required;
    public read-only Subversion servers are also exploitable.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
References:
    http://subversion.tigris.org/servlets/ReadMsg?list=announce&msgNo=125
    http://security.e-matters.de/advisories/082004.html


Solution: 
    All Subversion users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=dev-util/subversion-1.0.3"
    # emerge ">=dev-util/subversion-1.0.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-14] Buffer overflow in Subversion");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Buffer overflow in Subversion');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/subversion", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("le 1.0.2")
)) { security_warning(0); exit(0); }
