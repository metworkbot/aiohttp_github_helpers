.PHONY: doc all develop install clean test

all:
	python setup.py build

develop:
	python setup.py develop

install:
	python setup.py install

clean:
	rm -Rf *.egg-info
	rm -Rf aiohttp_github_helpers/__pycache__
	rm -Rf tests/__pycache__

test:
	flake8 .
	pytest

doc:
	cd doc && make html
