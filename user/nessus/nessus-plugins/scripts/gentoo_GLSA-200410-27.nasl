# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15579);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-27");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-27
(mpg123: Buffer overflow vulnerabilities)


    Buffer overflow vulnerabilities in the getauthfromURL() and http_open()
    functions have been reported by Carlos Barros. Additionally, the Gentoo
    Linux Sound Team fixed additional boundary checks which were found to be
    lacking.
  
Impact

    By enticing a user to open a malicious playlist or URL or making use of a
    specially-crafted symlink, an attacker could possibly execute arbitrary
    code with the rights of the user running mpg123.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.barrossecurity.com/advisories/mpg123_getauthfromurl_bof_advisory.txt


Solution: 
    All mpg123 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/mpg123-0.59s-r5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-27] mpg123: Buffer overflow vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mpg123: Buffer overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/mpg123", unaffected: make_list("ge 0.59s-r5"), vulnerable: make_list("lt 0.59s-r5")
)) { security_warning(0); exit(0); }
