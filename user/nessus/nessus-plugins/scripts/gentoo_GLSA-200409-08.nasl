# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14662);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200409-08");
 script_cve_id("CVE-2004-0755");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-08
(Ruby: CGI::Session creates files insecurely)


    The CGI::Session::FileStore implementation (and presumably
    CGI::Session::PStore), which allow data associated with a particular
    Session instance to be written to a file, writes to a file in /tmp with no
    regard for secure permissions. As a result, the file is left with whatever
    the default umask permissions are, which commonly would allow other local
    users to read the data from that session file.
  
Impact

    Depending on the default umask, any data stored using these methods could
    be read by other users on the system.
  
Workaround

    By changing the default umask on the system to not permit read access to
    other users (e.g. 0700), one can prevent these files from being readable by
    other users.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0755


Solution: 
    All Ruby users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-lang/ruby-your_version"
    # emerge ">=dev-lang/ruby-your_version"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-08] Ruby: CGI::Session creates files insecurely");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby: CGI::Session creates files insecurely');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/ruby", unaffected: make_list("rge 1.6.8-r11", "rge 1.8.0-r7", "ge 1.8.2_pre2"), vulnerable: make_list("lt 1.8.2_pre2")
)) { security_warning(0); exit(0); }
