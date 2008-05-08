mod_make: mod_make.la
	sudo apxs2 -i mod_make.la
	
mod_make.la: mod_make.c
	apxs2 -c mod_make.c
	
