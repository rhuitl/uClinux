
EXTRA_DIST = ulogd.txt ulogd.html ulogd.ps \
	mysql.table pgsql.table sqlite3.table mysql.table.ipaddr-as-string

dist-hook:
	sgml2txt ulogd.sgml
	sgml2latex --papersize=a4 --output=dvi ulogd.sgml
	dvips -t a4 -o ulogd.ps ulogd.dvi
	sgml2html -s 0 ulogd.sgml

