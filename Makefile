prefix = /usr/local
datarootdir = $(prefix)/share

all: install installservice

install:
	python3 -m compileall lobby_probe.py discord.py
	mkdir -p $(DESTDIR)$(datarootdir)/frame-gride/
	cp -r lobby_probe.py discord.py __pycache__ $(DESTDIR)$(datarootdir)/frame-gride/

installservice:
	install -m 644 systemd/frame-gride.service /usr/lib/systemd/system/
	systemctl enable frame-gride.service
	systemctl daemon-reload
	systemctl restart frame-gride.service
