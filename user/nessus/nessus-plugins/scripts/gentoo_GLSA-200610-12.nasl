# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22915);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-12");
 script_cve_id("CVE-2006-4154");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-12
(Apache mod_tcl: Format string vulnerability)


    Sparfell discovered format string errors in calls to the set_var
    function in tcl_cmds.c and tcl_core.c.
  
Impact

    A remote attacker could exploit the vulnerability to execute arbitrary
    code with the rights of the user running the Apache server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4154


Solution: 
    All mod_tcl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apache/mod_tcl-1.0.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-12] Apache mod_tcl: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache mod_tcl: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apache/mod_tcl", unaffected: make_list("ge 1.0.1"), vulnerable: make_list("lt 1.0.1")
)) { security_hole(0); exit(0); }
