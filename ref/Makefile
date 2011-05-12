all: doc1 doc2

clean:
	rm -rf *.pdf
	rm -rf *.log
	rm -rf *.aux
	rm -rf *.bbl

doc1: documentation.tex
	pdflatex documentation.tex

doc2: documentation2.tex
	pdflatex documentation2.tex
