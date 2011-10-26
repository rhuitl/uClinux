# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14537);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-04
(Pure-FTPd: Potential DoS when maximum connections is reached)


    Pure-FTPd contains a bug in the accept_client function handling the setup
    of new connections.
  
Impact

    When the maximum number of connections is reached an attacker could exploit
    this vulnerability to perform a Denial of Service attack.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
References:
    http://www.pureftpd.org


Solution: 
    All Pure-FTPd users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-ftp/pure-ftpd-1.0.18-r1"
    # emerge ">=net-ftp/pure-ftpd-1.0.18-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-04] Pure-FTPd: Potential DoS when maximum connections is reached");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pure-FTPd: Potential DoS when maximum connections is reached');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-ftp/pure-ftpd", unaffected: make_list("ge 1.0.18-r1"), vulnerable: make_list("le 1.0.18")
)) { security_warning(0); exit(0); }
