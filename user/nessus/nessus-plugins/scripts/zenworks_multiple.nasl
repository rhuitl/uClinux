#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18524);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2005-1543");
 script_bugtraq_id(13678);

 name["english"] = "Novell ZENworks Multiple Remote Pre-Authentication Buffer Overflow Vulnerabilities";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running Novell ZENworks Desktop or Server Management,
a remote desktop management software.

The remote version of this software is vulnerable to multiple heap and
stack overflow vulnerabilities which may be exploited by an attacker to
to execute arbitrary code on the remote host with the SYSTEM privileges.

Solution :

http://support.novell.com/cgi-bin/search/searchtid.cgi?/10097644.htm

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if ZENWorks is vulnerable to Buffer and Heap Overflow";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_require_ports(1761);
 exit(0);
}

port = 1761;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp (port);
if (!soc) exit(0);

version_req = raw_string (0x00, 0x06, 0x05, 0x01, 0x10, 0xe6, 0x01, 0x00, 0x34, 0x5a, 0xf4, 0x77, 0x80, 0x95, 0xf8, 0x77);

send (socket:soc, data:version_req);
buf = recv (socket:soc, length:20);
if ((strlen(buf) != 16))
  exit(0);

vers = ord (buf[1]);

if ( (vers != 6) &&
     (vers != 4) &&
     (vers != 3) )
  exit (0);

vers_comp = raw_string (0x00, 0x01);

send (socket:soc, data:vers_comp);
buf = recv (socket:soc, length:2);

#must be 0 or 2
if (strlen (buf) == 1)
  exit (0);

# we receive a msg first (sometimes)
if (strlen(buf) == 2)
{
 len = ord(buf[0]) * 256 + ord(buf[1]);
 buf = recv (socket:soc, length:len);
 if (strlen(buf) != len)
   exit(0);
}

auth_req = raw_string(0x02, 0x03) + crap(data:"A", length:0x203) + raw_string(0x00, 0x05) + "ak6lb" + raw_string(0x00, 0x07) + "UNKNOWN" + raw_string (0x00, 0x06);
send (socket:soc, data:auth_req);
buf = recv (socket:soc, length:100);

#server / desktop
rep1 = raw_string(0xff,0x9b);
rep2 = raw_string(0x00,0x00);
rep3 = raw_string(0x00,0x01);

if ((strlen(buf) == 2) && ((rep1 >< buf) || (rep2 >< buf) || (rep3 >< buf)))
  security_hole (port);

