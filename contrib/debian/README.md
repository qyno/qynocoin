
Debian
====================
This directory contains files used to package qynod/qyno-qt
for Debian-based Linux systems. If you compile qynod/qyno-qt yourself, there are some useful files here.

## qyno: URI support ##


qyno-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install qyno-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your qynoqt binary to `/usr/bin`
and the `../../share/pixmaps/qyno128.png` to `/usr/share/pixmaps`

qyno-qt.protocol (KDE)

