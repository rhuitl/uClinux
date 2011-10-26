#
# (C) Tenable Network Security
#
# Ref:
# Delivered-To: moderator for bugtraq@securityfocus.com
# To: kerberos-announce@MIT.EDU
# Subject: MITKRB5-SA-2003-004: Cryptographic weaknesses in Kerberos v4 protocol
# Reply-To: krbdev@mit.edu
# From: Tom Yu <tlyu@mit.edu>

if(description)
{
 script_id(11511);
 script_bugtraq_id(7113);
 script_cve_id("CVE-2003-0138");

 script_version ("$Revision: 1.5 $");
 name["english"] = "Kerberos IV cryptographic weaknesses";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Kerberos IV.

It has been demonstrated that the Kerberos IV protocol has inherent
design flaws that make it insecure to use.


See also : http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-004-krb4.txt

Solution : Use kerberos 5 instead. If you run Kerberos 5 with kerberos IV backward
compatibility, make sure you upgrade to version 1.3

Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Check for kerberos";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 exit(0);
}


req = raw_string(0x04, 0x02) + "nessus" + raw_string(0) + "NESSUS.ORG" + raw_string(0) + raw_string(0x3e, 0x8c, 0x25, 0xDC, 0x78) + "xkrbtgt" + raw_string(0) + "NESSUS.ORG" + raw_string(0);
soc = open_sock_udp(750);
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if(r && ord(r[0]) == 4)security_warning(port);
