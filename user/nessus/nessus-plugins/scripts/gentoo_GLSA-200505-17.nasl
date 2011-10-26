# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18381);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200505-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-17
(Qpopper: Multiple Vulnerabilities)


    Jens Steube discovered that Qpopper doesn\'t drop privileges to
    process local files from normal users (CVE-2005-1151). The upstream
    developers discovered that Qpopper can be forced to create group or
    world writeable files (CVE-2005-1152).
  
Impact

    A malicious local attacker could exploit Qpopper to overwrite
    arbitrary files as root or create new files which are group or world
    writeable.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1151
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1152


Solution: 
    All Qpopper users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/qpopper-4.0.5-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-17] Qpopper: Multiple Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qpopper: Multiple Vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/qpopper", unaffected: make_list("ge 4.0.5-r3"), vulnerable: make_list("lt 4.0.5-r3")
)) { security_warning(0); exit(0); }
