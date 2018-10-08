all:
	python setup.py build

develop:
	python setup.py develop

install:
	python setup.py install

clean:
	rm -Rf *.egg-info
