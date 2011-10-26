# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14747);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-20");
 script_cve_id("CVE-2004-0805");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-20
(mpg123: Buffer overflow vulnerability)


    mpg123 contains a buffer overflow in the code that handles layer2
    decoding of media files.
  
Impact

    An attacker can possibly exploit this bug with a specially-crafted mp3 or mp2 file
    to execute arbitrary code with the permissions of the user running mpg123.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/374433/2004-09-05/2004-09-11/0
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0805


Solution: 
    All mpg123 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-sound/mpg123-0.59s-r4"
    # emerge ">=media-sound/mpg123-0.59s-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-20] mpg123: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mpg123: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/mpg123", unaffected: make_list("ge 0.59s-r4"), vulnerable: make_list("le 0.59s-r3")
)) { security_warning(0); exit(0); }
