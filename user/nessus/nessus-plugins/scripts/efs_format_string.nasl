#
# (C) Tenable Network Security
#


if (description) {
  script_id(21039);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1159", "CVE-2006-1160", "CVE-2006-1161");
  script_bugtraq_id(17046);
  if (defined_func("script_xref")) 
  {
    script_xref(name:"OSVDB", value:"23791");
    script_xref(name:"OSVDB", value:"23792");
    script_xref(name:"OSVDB", value:"23793");
  }

  script_name(english:"Easy File Sharing Web Server Format String Vulnerability");
  script_summary(english:"Sends a format string to EFS web server");
 
  desc = "
Synopsis :

The remote web server suffers from a format string vulnerability. 

Description :

The remote host is running Easy File Sharing Web Server, a file
sharing application / web server for Windows. 

The version of Easy File Sharing Web Server installed on the remote
host may crash if it receives requests with an option parameter
consisting of a format string.  It is unknown whether this issue can
be exploited to execute arbitrary code on the remote host, although it
is likely the case. 

In addition, the application reportedly allows remote users to upload
arbitrary files to arbitrary locations on the affected host.  An
attacker may be able to leverage this issue to completely compromise
the host by placing them in the startup folder and waiting for a
reboot. 

Additionally, it fails to sanitize input to the 'Description' field
when creating a folder or uploading a file, which could lead to
cross-site scripting attacks. 

Note that by default the application runs with the privileges of the
user who started it, although it can be configured to run as a
service. 

See also :

http://www.securityfocus.com/archive/1/427158/30/0/threaded

Solution :

Unknown at this time. 

Risk factor : 

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_DENIAL);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


if ( ! thorough_tests ) exit(0);

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the banner indicates it's EFS.
banner = get_http_banner(port:port);
if (!banner || "Server: Easy File Sharing Web Server" >!< banner) exit(0);


# Try to crash it.
req = http_get(item:"/?%25n", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);


# If we didn't get anything back...
if (res == NULL) {
  # The server doesn't crash right away so try for a bit to open a connection.
  tries = 5;
  for (iter=0; iter<=tries; iter++) {
    soc = http_open_socket(port);
    if (soc) {
      failed = 0;
      close(soc);
      sleep(5);
    }
    else {
      failed++;
      if (failed > 1) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
