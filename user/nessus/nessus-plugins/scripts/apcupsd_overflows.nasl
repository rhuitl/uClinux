#
# This script was written by Renaud Deraison
#
# GPL
#

if(description)
{
  script_id(11484);
  script_bugtraq_id(2070, 6828, 7200);
  script_cve_id("CVE-2001-0040", "CVE-2003-0098", "CVE-2003-0099");
  if ( defined_func("script_xref") ) script_xref(name:"SuSE", value:"SUSE-SA:2003:022");

  
  script_version ("$Revision: 1.6 $");
 
  script_name(english:"apcupsd overflows");
 
  desc["english"] = "
The remote apcupsd, according to its version number,
is vulnerable to a buffer overflow which could
allow an attacker to gain a root shell on this host.

*** Nessus solely relied on the version number of the 
*** remote server, so this might be a false positive

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks the version of apcupsd";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
  family["english"] = "Gain root remotely";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "apcnisd_detect.nasl");
  script_require_ports("Services/apcnisd", 7000);

  exit(0);
}

port = get_kb_item("Services/apcnisd");
if (! port) port = 7000;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
req = raw_string(0x00, 0x06) + "status";
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if("APC" >< r && "MODEL" >< r)
{
  r = strstr(r, "RELEASE");
  if(ereg(pattern:"RELEASE.*: (3\.([0-7]\..*|8\.[0-5][^0-9]|10\.[0-4])|[0-2]\..*)", string:r))
       security_hole(port);

}
