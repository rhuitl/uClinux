# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22285);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-23");
 script_cve_id("CVE-2006-3121", "CVE-2006-3815");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-23
(Heartbeat: Denial of Service)


    Yan Rong Ge discovered that the peel_netstring() function in
    cl_netstring.c does not validate the "length" parameter of user input,
    which can lead to an out-of-bounds memory access when processing
    certain Heartbeat messages (CVE-2006-3121). Furthermore an unspecified
    local DoS issue was fixed (CVE-2006-3815).
  
Impact

    By sending a malicious UDP Heartbeat message, even before
    authentication, a remote attacker can crash the master control process
    of the cluster.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3121
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3815


Solution: 
    All Heartbeat users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-cluster/heartbeat-2.0.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-23] Heartbeat: Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Heartbeat: Denial of Service');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-cluster/heartbeat", unaffected: make_list("ge 2.0.7"), vulnerable: make_list("lt 2.0.7")
)) { security_warning(0); exit(0); }
