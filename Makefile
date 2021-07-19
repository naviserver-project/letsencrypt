ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

MODNAME = letsencrypt
TCL = letsencrypt-procs.tcl

include  $(NAVISERVER)/include/Makefile.module

install:
	$(INSTALL_SH) letsencrypt.tcl $(INSTSRVPAG)/	
