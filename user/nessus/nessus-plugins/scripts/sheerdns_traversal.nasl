#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  Date: Sun, 13 Apr 2003 18:00:13 +0200
#  From: Jedi/Sector One <j@pureftpd.org>
#  To: bugtraq@securityfocus.com
#  Subject: Multiple vulnerabilities in SheerDNS


if(description)
{
 script_id(11535);
 script_bugtraq_id(7335, 7336);
 script_version ("$Revision: 1.5 $");
 
 
 name["english"] = "SheerDNS directory traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server seems to be running SheerDNS 1.0.0 or older.

This version is vulnerable to several flaws allowing :
	- A remote attacker to read certain files with predefined names
	  (A, PTR, CNAME, ...)

	- A local attacker to read the first line of arbitrary files with the 
	  privileges of the DNS server (typically root)

	- A local attacker to execute arbitrary code through a buffer overflow

Solution : Upgrade to SheerDNS 1.0.1 or disable this service
Risk factor : Low (remotely) / High (locally)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the remote DNS server handles malformed names";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);

 exit(0);
}


function check(str)
{ 
  local_var req, r, soc;

  req = raw_string(0x00, 0x04,
		 0x01, 0x00,
		 0x00, 0x01,
		 0x00, 0x00,
		 0x00, 0x00,
		 0x00, 0x00, 
		strlen(str)) + str +
 	raw_string(0x00, 0x00, 0x01, 0x00, 0x01);

 soc = open_sock_udp(53);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096);
 close(soc);

 return r;
}


r = check(str:"localhost");
if(!r)exit(0); # No reply -> quit
if("localhost" >!< r)exit(0); # Does not echo back the query -> quit

r = check(str:"../nessus");
if(!r)exit(0);	# No reply -> good
if("nessus" >< r)exit(0); # Did not modify the name -> good


security_warning(port:53, proto:"udp");
