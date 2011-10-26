#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# 
#
# This script simply attempts to log into the realm FR.NESSUS.ORG
# with a username of "whatever". It does not check for any flaw (which
# is bad), but that may change in the future.
# 

if(description)
{
 script_id(11512);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0007");
 script_bugtraq_id(11078, 11079, 6712, 6713, 6714, 7184, 7185);
 script_cve_id("CVE-2003-0072", "CVE-2003-0082", "CVE-2003-0059", "CVE-2003-0060", "CVE-2002-0036", "CVE-2003-0028", "CVE-2003-0138", "CVE-2003-0139");
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2003:091-01");

 script_version ("$Revision: 1.9 $");
 name["english"] = "Kerberos 5 issues";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Kerberos 5.

There are multiple flaws which affect this product,
make sure you are running the latest version with
the latest patches.

*** Nessus could not check for any of the flaws
*** and solely relied on the presence of the service
*** to issue an alert, so this might be a false positive

Solution : Upgrade to the latest version of MIT kerberos
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Check for kerberos";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 2 ) exit(0);


name = "whatever";

len = strlen(name);
#len = 1024;
if(len > 256)
{
 len = raw_string(0x82, len / 256, len % 256);
#len = raw_string(0x84, 0x7F, 0xFF, 0xFF, 0xFF);
}
else len = raw_string(len % 256);

pk_lenE = 12 + strlen(name);
if(strlen(name) > 256)
 pk_lenE = raw_string(0x82, pk_lenE / 256, pk_lenE % 256);
else
 pk_lenE = raw_string( pk_lenE % 256);
 
 
pk_lenD = 186 + strlen(name);
if(strlen(name) > 256)pk_lenD += 14;
if(pk_lenD > 256)
 pk_lenD = raw_string(0x82, pk_lenD / 256, pk_lenD % 256);
else
 pk_lenD = raw_string(0x81, pk_lenD % 256);
 
 
 
pk_lenC = 183 + strlen(name);
if(strlen(name) > 256)pk_lenC += 12;
if(pk_lenC > 256)
 pk_lenC = raw_string(0x82, pk_lenC / 256, pk_lenC % 256);
else
 pk_lenC = raw_string(0x81, pk_lenC % 256);
 

pk_lenB = 170 + strlen(name);
if(strlen(name) > 256)pk_lenB += 10;
if(pk_lenB > 256)
 pk_lenB = raw_string(0x82, pk_lenB / 256, pk_lenB % 256);
else
 pk_lenB = raw_string(0x81, pk_lenB % 256);
 

pk_lenA = 167 + strlen(name);
if(strlen(name) > 256)pk_lenA += 8;
if(pk_lenA > 256)
 pk_lenA = raw_string(0x82, pk_lenA / 256, pk_lenA % 256);
else
 pk_lenA = raw_string(0x81, pk_lenA % 256);
 

pk_len0 = 11 + strlen(name);
if(strlen(name) > 256) pk_len0 += 6;
if(pk_len0 > 256)
{
 pk_len0 = raw_string(0x82, pk_len0 / 256, pk_len0 % 256);
}
else pk_len0 = raw_string(pk_len0 % 256);

pk_len1 = 4 + strlen(name);
if(strlen(name) > 256) pk_len1 += 4;
if(pk_len1 > 256)
{
 pk_len1 = raw_string(0x82, pk_len1 / 256, pk_len1 % 256);
}
else pk_len1 = raw_string(pk_len1 % 256);

pk_len2 = 2 + strlen(name);
if(strlen(name) > 256) pk_len2 += 2;

if(pk_len2 > 256)
{
 pk_len2 = raw_string(0x82, pk_len2 / 256, pk_len2 % 256);
}
else pk_len2 = raw_string(pk_len2 % 256);



req = raw_string(
		 0x6A) + pk_lenD + raw_string(0x30)+ pk_lenC + raw_string(0xA1, 0x03,
		 0x02, 0x01, 0x05, 0xA2, 0x03,
		 0x02, 0x01, 0x0A, 0xA4) + pk_lenB + raw_string(0x30) + pk_lenA +
		 raw_string(
		 0xA0, 0x07, 0x03, 0x05, # ??
		 0x00, 0x00, 0x00, 0x00, 0x00, 0xA1)+ pk_lenE + raw_string(
		 0x30) + pk_len0 + raw_string(0xA0, 0x03, 
		 0x02, 0x01, 0x01,
		 0xA1) + pk_len1 + raw_string( 0x30) + pk_len2 + 
		 raw_string(0x1B) + len + name + raw_string(
		 0xA2, 0x0F, 0x1B, 0x0D, 
		 0x46, 0x52, 0x2E, 0x4E, 0x45, 0x53, 0x53, 0x55,
		 0x53, 0x2E, 0x4F, 0x52, 0x47, 0xA3, 0x22, 0x30,
		 0x20, 0xA0, 0x03, 0x02, 0x01, 0x00, 0xA1, 0x19,
		 0x30, 0x17, 0x1B, 0x06, 0x6B, 0x72, 0x62, 0x74,
		 0x67, 0x74, 0x1B, 0x0D, 0x46, 0x52, 0x2E, 0x4E,
		 0x45, 0x53, 0x53, 0x55, 0x53, 0x2E, 0x4F, 0x52,
		 0x47, 0xA4, 0x11, 0x18, 0x0F, 0x32, 0x30, 0x30,
		 0x33, 0x30, 0x34, 0x30, 0x33, 0x31, 0x32, 0x35,
		 0x37, 0x33, 0x38, 0x5A, 0xA5, 0x11, 0x18, 0x0F,
		 0x32, 0x30, 0x30, 0x33, 0x30, 0x34, 0x30, 0x33,
		 0x32, 0x32, 0x35, 0x37, 0x33, 0x38, 0x5A, 0xA7,
		 0x06, 0x02, 0x04, 0x3E, 0x8c, 0x2f, 0xC2, 0xA8,
		 0x08, 0x30, 0x06, 0x02, 0x01, 0x10, 0x02, 0x01,
		 0x01, 0xA9, 0x20, 0x30, 0x1E, 0x30, 0x0D, 0xA0,
		 0x03, 0x02, 0x01, 0x02, 0xA1, 0x06, 0x04, 0x04,
		 0x0A, 0xA3, 0x9c, 0x12, 0x30, 0x0D, 0xA0, 0x03,
		 0x02, 0x01, 0x02, 0xA1, 0x06, 0x04, 0x04, 0x0A,
		 0xA3, 0x9F, 0x01);
		 
		 
foreach port (make_list(88, 750))
{		 
 soc = open_sock_udp(port);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096);
 close(soc);

 if(strlen(r) > 10 && ord(r[10]) == 5)
 {
 security_hole(port:port, proto:"udp"); 
 }
}
		 
