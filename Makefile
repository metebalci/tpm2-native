
clean:
	rm -rf dist

dist: clean
	python setup.py sdist

pypi: dist
	twine upload dist/*
