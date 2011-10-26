# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17330);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-18");
 script_cve_id("CVE-2004-1292");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-18
(Ringtone Tools: Buffer overflow vulnerability)


    Qiao Zhang has discovered a buffer overflow vulnerability in the
    \'parse_emelody\' function in \'parse_emelody.c\'.
  
Impact

    A remote attacker could entice a Ringtone Tools user to open a
    specially crafted eMelody file, which would potentially lead to the
    execution of arbitrary code with the rights of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1292


Solution: 
    All Ringtone Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-misc/ringtonetools-2.23"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-18] Ringtone Tools: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ringtone Tools: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-misc/ringtonetools", unaffected: make_list("ge 2.23"), vulnerable: make_list("lt 2.23")
)) { security_warning(0); exit(0); }
