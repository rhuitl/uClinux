-include ../user.mak

all:
	@echo "Nothing to build for jQuery UI"

clean:
	@echo "Nothing to clean for jQuery UI"

romfs:
	$(ROMFSINST) -d js/jquery-1.3.2.min.js /home/httpd/js/jquery-1.3.2.min.js
	$(ROMFSINST) -d js/jquery-ui-1.7.2.custom.min.js /home/httpd/js/jquery-ui-1.7.2.custom.min.js
	$(ROMFSINST) -d development-bundle/themes/base/images /home/httpd/img/
	for f in development-bundle/themes/base/*.css ;\
	do \
		$(ROMFSINST) -d $$f /home/httpd/css/`basename $$f` ;\
	done
