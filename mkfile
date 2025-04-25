</$objtype/mkfile

TARG = iscsisrv
DIRS =  iscsifs

HFILES =\
	iscsi.h

BIN=/$objtype/bin/ip

</sys/src/cmd/mkmany

all:V:	$DIRS

$DIRS:V:
	cd iscsifs
	mk all

install:V:	installdirs

installdirs:V:
	cd iscsifs
	mk install

clean:V:
	@{cd iscsifs
	mk clean}
	rm -f [$OS].* *.[$OS]

nuke:V:
	@{cd iscsifs
	mk nuke}
	rm -f *.[$OS] y.tab.? y.debug y.output [$OS].$TARG $TARG
