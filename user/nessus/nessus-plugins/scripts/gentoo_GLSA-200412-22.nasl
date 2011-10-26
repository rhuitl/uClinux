# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16021);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-22");
 script_cve_id("CVE-2004-1284");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-22
(mpg123: Playlist buffer overflow)


    Bartlomiej Sieka discovered that mpg123 contains an unsafe
    strcat() to an array in playlist.c. This code vulnerability may lead to
    a buffer overflow.
  
Impact

    A remote attacker could craft a malicious playlist which, when
    used, would result in the execution of arbitrary code with the rights
    of the user running mpg123.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://tigger.uic.edu/~jlongs2/holes/mpg123.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1284


Solution: 
    All mpg123 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/mpg123-0.59s-r8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-22] mpg123: Playlist buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mpg123: Playlist buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/mpg123", unaffected: make_list("ge 0.59s-r8"), vulnerable: make_list("lt 0.59s-r8")
)) { security_warning(0); exit(0); }
