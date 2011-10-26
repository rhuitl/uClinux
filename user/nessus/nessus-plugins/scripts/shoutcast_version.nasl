#
# (C) Tenable Network Security
#


if (description) {
  script_id(10717);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2001-1304");
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"595");
  }

  name["english"] = "SHOUTcast Server User-Agent / Host Header Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host is running a SHOUTcast server that is prone to denial of
service attacks. 

Description :

The remote host is running SHOUTcast Server, a streaming media server
from Nullsoft.

According to its banner, the installed version of SHOUTcast server will
reportedly crash when it receives several HTTP requests with overly long
User-Agent and/or Host request headers.  It is not known whether this
issue can be exploited to execute arbitrary code. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2001-08/0048.html

Solution : 

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for User-Agent / Host header denial of service vulnerability in SHOUTcast Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


# Loop through various ports and request an invalid stream to get the server's version number.
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8000);
foreach port (ports) {
  if (get_port_state(port)) {
    req = http_get(item:"/stream/0", port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if the version is 1.8.2 or lower.
    if (egrep(pattern:"SHOUTcast Distributed Network Audio Server.*v(0\..*|1\.([0-7]\..*|8\.[0-2]))[^0-9]", string:res)) {
      security_warning(port);
      exit(0);
    }
  }
}
