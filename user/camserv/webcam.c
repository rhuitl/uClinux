/*  webcam - A very basic cgi for displaying webcam imagery from the camserv daemon
 *
 *  Copyright (C) 2005, Damion de Soto (damion@snapgear.com)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "camconfig.h"

int main(int argc, char *argv[]) {
	char *serverip;
	char *ptr;
	CamConfig *camcfg;
	int listen_port = 9192;
	FILE *fp;
	serverip = getenv("SERVER_NAME");

	ptr = strrchr(serverip, ':');
	if (ptr)
		*ptr = '\0';

	if ((fp = fopen(DATDIR"/camserv.cfg", "r" )) != NULL) {
		if ((camcfg = camconfig_read(fp)) != NULL )
			listen_port = camconfig_query_def_int(camcfg, SEC_SOCKET,
		                           "listen_port", CAMCONFIG_DEF_LISTEN_PORT );
		fclose(fp);
	}

	puts("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\n>");
	puts("<html>\n<head>\n<title>WEBCAM</title>\n");
	puts("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\">\n");
	puts("<script LANGUAGE=\"JavaScript\">\n<!--\n");
	puts(
    "var speed = 1;\n"
    "var y = 1;\n"
    "var x = speed + y;\n"
    "var time = x - y;\n"
    "var now;\n"
    "campicture = new Image();\n"
	"    function stopClock() {\n"
	"        x = \"off\";\n"
	"        document.form0.clock.value = x;\n"
	"    }\n"
	"    function startClock() {\n"
	"            if (x != \"off\") {\n"
	"        x = x - y;\n"
	"        document.form0.clock.value = x;\n"
	"        if (x <= 1)\n"
	"            {\n"
	"              reload()\n"
	"            }\n"
	"        timerID = setTimeout(\"startClock()\", 1000);\n"
	"            }\n"
	"    }\n");
	printf(
	"    function reload() {\n"
	"        now = new Date();\n"
	"        var camImg = \"http://%s:%d/singleframe/\" + \"?\" + now.getTime();\n"
	"        document.campicture.src = camImg;\n"
	"        x = speed;\n"
	"        document.form0.clock.value = x;\n"
	"    }\n", serverip, listen_port);
	puts("// -->\n</script>\n</head>\n");
	puts("<body>\n<script language=\"JavaScript\">\n");
	printf("<!--> <img src=\"http://%s:%d/\">\n", serverip, listen_port);
	printf("<!--\n"
	"    if (navigator.userAgent.indexOf(\"MSIE\") > -1) {\n"
	"        document.write(\"<FORM action=\\\"webcam.html\\\" name=\\\"form0\\\">\");\n"
	"        document.write(\"<IMG src=\\\"webcam.jpg\\\" name=\\\"campicture\\\" alt=\\\"webcam\\\" border=0 reload=\\\"60\\\">\");\n"
	"        document.write(\"<INPUT type=\\\"hidden\\\" name=\\\"clock\\\" size=\\\"3\\\" value=\\\"\\\">\")\n"
	"        document.write(\"</FORM>\");\n"
	"        startClock();\n"
	"    } else {\n"
	"        document.write(\"<img src=\\\"http://%s:%d/\\\">\");\n"
	"    }\n", serverip, listen_port);
	puts("// -->\n</script>\n</body>\n</html>\n");
	return 0;
}
