# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-28.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18159);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-28");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-28
(Heimdal: Buffer overflow vulnerabilities)


    Buffer overflow vulnerabilities in the slc_add_reply() and
    env_opt_add() functions have been discovered by Gael Delalleau in the
    telnet client in Heimdal.
  
Impact

    Successful exploitation would require a vulnerable user to connect
    to an attacker-controlled host using the telnet client, potentially
    executing arbitrary code with the permissions of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0468
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0469


Solution: 
    All Heimdal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/heimdal-0.6.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-28] Heimdal: Buffer overflow vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Heimdal: Buffer overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/heimdal", unaffected: make_list("ge 0.6.4"), vulnerable: make_list("lt 0.6.4")
)) { security_warning(0); exit(0); }
