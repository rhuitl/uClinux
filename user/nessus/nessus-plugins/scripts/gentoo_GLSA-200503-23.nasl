# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17579);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-23");
 script_cve_id("CVE-2005-0764");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-23
(rxvt-unicode: Buffer overflow)


    Rob Holland of the Gentoo Linux Security Audit Team discovered
    that rxvt-unicode fails to properly check input length.
  
Impact

    Successful exploitation would allow an attacker to execute
    arbitrary code with the permissions of the user running rxvt-unicode.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0764


Solution: 
    All rxvt-unicode users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-terms/rxvt-unicode-5.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-23] rxvt-unicode: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rxvt-unicode: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-terms/rxvt-unicode", unaffected: make_list("ge 5.3", "lt 4.8"), vulnerable: make_list("lt 5.3")
)) { security_warning(0); exit(0); }
