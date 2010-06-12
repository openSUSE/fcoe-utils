## known to work with asciidoc version 8.4.5
## and the DocBook XSL Stylesheets version 1.75.2

MAN_8_TXT := fcoeadm.txt fcoemon.txt fipvlan.txt fcrls.txt fcnsq.txt
MAN_TXT := $(MAN_8_TXT)
MAN_8 := $(patsubst %.txt,%.8,$(MAN_8_TXT))
MAN := $(MAN_8)
MAN_XML := $(patsubst %.txt,%.xml,$(MAN_TXT))

man: $(MAN)

XSLTPROC_OPTS := --param man.justify 1
A2X_OPTS := -d manpage --xsltproc-opts='$(XSLTPROC_OPTS)'

%.8: %.txt
	a2x -f manpage $(A2X_OPTS) $<

clean:
	rm -f $(MAN_XML)

.DEFAULT_GOAL := man
.PHONY: man clean
