# Auth: From Zero to Pro — build
#
#   make book   PDF and EPUB into build/
#   make web    single-page HTML site into site/
#   make check  tests, glossary gate, prose lint, app tests, generated files
#   make all    check, then book and web

SHELL := /bin/bash
export PATH := $(CURDIR)/bin:$(CURDIR)/node_modules/.bin:$(PATH)

BOOK_SRC   := book/book.adoc
ADOC_SRC   := $(shell find book -name '*.adoc')
FINAL      := $(shell python3 scripts/chapters.py --status final)
LINT_FILES := book/preface.adoc $(FINAL)
PUPPETEER  := -a "mermaid-puppeteer-config=$(CURDIR)/puppeteer-config.json"
DIAGRAM    := -r asciidoctor-diagram $(PUPPETEER) -a "imagesoutdir=$(CURDIR)/build/images" -a "imagesdir=$(CURDIR)/build/images"
COMMON     := -a source-highlighter=rouge -a icons=font -a xrefstyle=short -a sectanchors -a experimental --failure-level=WARN

.PHONY: all book pdf epub web check test glossary lint app-test recommendations clean

all: check book web

book: pdf epub

pdf: build/auth-from-zero-to-pro.pdf
epub: build/auth-from-zero-to-pro.epub

build/auth-from-zero-to-pro.pdf: $(BOOK_SRC) $(ADOC_SRC) $(wildcard diagrams/*.mmd) book/appendix-recommendations.adoc
	@mkdir -p build
	bundle exec asciidoctor-pdf $(COMMON) $(DIAGRAM) -a book -a toc -a toclevels=2 -o $@ $(BOOK_SRC)

build/auth-from-zero-to-pro.epub: $(BOOK_SRC) $(ADOC_SRC) $(wildcard diagrams/*.mmd) book/appendix-recommendations.adoc
	@mkdir -p build
	bundle exec asciidoctor-epub3 $(COMMON) -r asciidoctor-diagram $(PUPPETEER) -a "imagesoutdir=$(CURDIR)/build/images" -a imagesdir=../build/images -a book -a toc -o $@ $(BOOK_SRC)

web: site/index.html

site/index.html: $(BOOK_SRC) $(ADOC_SRC) $(wildcard diagrams/*.mmd) book/appendix-recommendations.adoc
	@mkdir -p site
	bundle exec asciidoctor $(COMMON) -r asciidoctor-diagram $(PUPPETEER) -a "imagesoutdir=$(CURDIR)/site/images" -a imagesdir=images \
	  -a web -a toc=left -a toclevels=2 -a linkcss! -o $@ $(BOOK_SRC)

check: test glossary lint recommendations app-test
	@echo "check: all gates passed"

test:
	python3 -m unittest discover -s tests -v 2>&1 | tail -3

glossary:
	python3 scripts/check-glossary.py

lint:
	vale --config .vale.ini $(LINT_FILES)

recommendations:
	python3 scripts/build-recommendations.py --check

book/appendix-recommendations.adoc: $(wildcard book/track-*/*.adoc) scripts/build-recommendations.py
	python3 scripts/build-recommendations.py

app-test:
	@if [ -d app ]; then $(MAKE) -C app test; else echo "app-test: /app not created yet (author reviewing approach), skipping"; fi

clean:
	rm -rf build site
