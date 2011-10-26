#
# This script only checks if port 4711 is open and if it reports banner which contains string "eMule".
# Usually this port is used for Web Server by eMule client and eMulePlus (P2P software).
# This script has been tested on eMule 0.30e; 0.42 c,d,e,g; eMulePlus v.1 i,j,k.
#

if(description)
{
  script_id(12233);
  script_cve_id("CVE-2004-1892");
  script_bugtraq_id(10039);
  script_version ("$Revision: 1.5 $");
 
  script_name(english:"eMule Plus Web Server detection");
 
  desc["english"] = "
eMule Web Server works on this port. Some versions of this P2P client 
are vulnerable to a DecodeBase16 buffer overflow which would allow an 
attacker to execute arbitrary code.

Thanks to Kostya Kortchinsky for his posting to bugtraq.

Known Vulnerable clients:
eMule 0.42a-d
eMule 0.30e
eMulePlus <1k

See also : http://security.nnov.ru/search/news.asp?binid=3572

* Note: This script only checks if port 4711 is open and if 
it reports banner which contains string eMule. *

Solution: disable eMule Web Server or upgrade to a bug-fixed version 
(eMule 0.42e, eMulePlus 1k or later)

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect eMule Web Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 A.Kaverin"); 
  family["english"] = "Peer-To-Peer File Sharing";
  script_family(english:family["english"]);
  script_dependencies("find_service.nes");
  script_require_ports(4711);
  exit(0);
}


include("http_func.inc"); 

port = 4711;

if(! get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if ( banner && "eMule" >< banner )
  {
  security_warning(port);
  }

exit(0);


  
