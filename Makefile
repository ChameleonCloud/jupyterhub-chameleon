.PHONY: build
build:
	@ rm -rf build dist
	python setup.py sdist bdist_wheel

.PHONY: publish
publish:
	twine upload dist/*
