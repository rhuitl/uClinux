# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20417);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-07
(ClamAV: Remote execution of arbitrary code)


    Zero Day Initiative (ZDI) reported a heap buffer overflow
    vulnerability. The vulnerability is due to an incorrect boundary check
    of the user-supplied data prior to copying it to an insufficiently
    sized memory buffer. The flaw occurs when the application attempts to
    handle compressed UPX files.
  
Impact

    For example by sending a maliciously crafted UPX file into a mail
    server that is integrated with ClamAV, a remote attacker\'s supplied
    code could be executed with escalated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0162


Solution: 
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.88"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-07] ClamAV: Remote execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.88"), vulnerable: make_list("lt 0.88")
)) { security_hole(0); exit(0); }
