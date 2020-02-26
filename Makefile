
clean:
	rm -rf dist

upload:  clean
	python setup.py sdist
	twine upload dist/*
