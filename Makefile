ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

include  $(NAVISERVER)/include/Makefile.module

install:
	$(INSTALL_SH) letsencrypt.tcl $(INSTSRVPAG)/	
