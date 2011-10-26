# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20999);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-01
(WordPress: SQL injection vulnerability)


    Patrik Karlsson reported that WordPress 1.5.2 makes use of an
    insufficiently filtered User Agent string in SQL queries related to
    comments posting. This vulnerability was already fixed in the
    2.0-series of WordPress.
  
Impact

    An attacker could send a comment with a malicious User Agent
    parameter, resulting in SQL injection and potentially in the subversion
    of the WordPress database. This vulnerability wouldn\'t affect WordPress
    sites which do not allow comments or which require that comments go
    through a moderator.
  
Workaround

    Disable or moderate comments on your WordPress blogs.
  

Solution: 
    All WordPress users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-2.0.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-01] WordPress: SQL injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: SQL injection vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 2.0.1"), vulnerable: make_list("le 1.5.2")
)) { security_warning(0); exit(0); }
