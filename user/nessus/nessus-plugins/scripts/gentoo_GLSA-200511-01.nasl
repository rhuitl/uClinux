# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20140);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-01");
 script_cve_id("CVE-2005-2958");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-01
(libgda: Format string vulnerabilities)


    Steve Kemp discovered two format string vulnerabilities in the
    gda_log_error and gda_log_message functions. Some applications may pass
    untrusted input to those functions and be vulnerable.
  
Impact

    An attacker could pass malicious input to an application making
    use of the vulnerable libgda functions, potentially resulting in the
    execution of arbitrary code with the rights of that application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2958


Solution: 
    All libgda users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=gnome-extra/libgda-1.2.2-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-01] libgda: Format string vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libgda: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "gnome-extra/libgda", unaffected: make_list("ge 1.2.2-r1"), vulnerable: make_list("lt 1.2.2-r1")
)) { security_warning(0); exit(0); }
