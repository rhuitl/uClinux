CURR_DIR :=$(shell pwd)

export CURR_DIR

.PHONY: get_version

all: clean get_version get_options 

get_version:
	@if [ ! -d $(KERNEL_SOURCE)/ ]; then \
		echo "";\
		echo "$(KERNEL_SOURCE) directory does not exist. Please edit the file 'config'";\
		echo "in this directory and set KERNEL_SOURCE to the correct location of your ";\
		echo "kernel source.";\
		echo "";\
		echo "You are currently running kernel version `uname -r`, the source code should";\
		echo "be for this version.";\
		echo "";\
		exit 1;\
	fi
	@if [ ! -f $(KERNEL_SOURCE)/include/linux/version.h ]; then \
		echo "$(KERNEL_SOURCE)/include/linux/version.h is missing. Please run make config";\
		echo "in your kernel source tree";\
		exit 1;\
	fi

	$(CC) -I$(KERNEL_SOURCE)/include get_version.c -o get_version

get_options:
	$(MAKE) -f $(CURR_DIR)/Makefile.get_options -C $(KERNEL_SOURCE) get_version_target

clean:
	$(RM) get_version make.opts 

distclean: clean

