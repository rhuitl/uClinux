#
# (C) Tenable Network Security
#


if (description) {
  script_id(20341);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3534");
  script_bugtraq_id(16029);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21848");
  }

  script_name(english:"Network Block Device Server Buffer Overflow Vulnerability");
  script_summary(english:"Checks for a buffer overflow vulnerability in a Network Block Device server");

  desc = "
Synopsis :

The remote service is affected by a buffer overflow vulnerability. 

Description :

The version of the Network Block Device (NBD) server installed on the
remote host does not properly check the size of read requests before
filling a dynamically-allocated buffer.  Using a specially-crafted
read request, an attacker can overwrite this buffer, which may crash
the affected server or allow for the execution of arbitrary code. 

See also :

http://sourceforge.net/mailarchive/forum.php?thread_id=9201144&forum_id=40388
http://sourceforge.net/project/shownotes.php?release_id=380202&group_id=13229

Solution :

Upgrade to NBD 2.8.3 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("nbd_detect.nasl");
  script_require_ports("Services/nbd", 2000);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/nbd");
if (!port) exit(0);

if (!get_tcp_port_state(port)) exit(0);


# nb: we need to read 1MB of data to check for the flaw so let's
#     only run the check if we're really interested in finding flaws.
if (!thorough_tests && report_paranoia < 2) {
    if (log_verbosity > 1) debug_print("skipped; set thorough_checks or report_paranoia to run!", level:0);
  exit(0);
}


# Establish a connection and examine the banner.
soc = open_sock_tcp(port);
if (soc) {
  res = recv(socket:soc, length:256);
  if (res == NULL) exit(0);

  # Define some constants.
  bufsize = 1024*1024;                  # defined in <linux/nbd.h>
  nbd_reply_size = 32;                  # size of the nbd_reply structure
  read_size = bufsize + 100;            # a bit more so we're we're reading correctly.

  # We'll send an initial request for something beyond that; if it works,
  # then someone's increased it and our exploit won't work.
  req = raw_string(
    mkdword(0x25609513),                # NBD_REQUEST_MAGIC
    mkdword(0),                         # NBD_CMD_READ
    "NESSUS  ",                         # handle (unused)
    mkdword(0), mkdword(0),             # where to start reading.
    mkdword(bufsize+1)                  # how much to read (too much).
  );
  send(socket:soc, data:req);
  res = recv(socket:soc, length:read_size);
  len = strlen(res);

  if (len == bufsize+1) exit(0);
  else if (len > 0) {
    if (log_verbosity > 1) debug_print("read returned a strange amount - ", len, " bytes!", level:0);
    exit(1);
  }

  # The server didn't return anything, possibly because the request was
  # too big -- it just closes the socket without returning anything -- 
  # so try to exploit the flaw now.
  req = raw_string(
    mkdword(0x25609513),                # NBD_REQUEST_MAGIC
    mkdword(0),                         # NBD_CMD_READ
    "NESSUS  ",                         # handle
    mkdword(0), mkdword(0),             # where to start reading
    mkdword(bufsize)                    # how much to read (bufsize)
  );
  send(socket:soc, data:req);
  res = recv(socket:soc, length:read_size);

  # Check the socket again in the unlikely event that the exploit worked.
  if (!strlen(res)) {
    soc2 = open_sock_tcp(port);
    if (soc2) {
      res2 = recv(socket:soc, length:256);
      close(soc2);
    }
  }
  close(soc);

  # There's a problem if... 
  if (
    # we didn't get a second response or...
    isnull(res2) || 
    # the first response was the requested buffer plus the reply structure.
    strlen(res) == bufsize + nbd_request_sz
  ) {
    security_warning(port);
    exit(0);
  }
}
