.PHONY: publish
publish:
	@ rm -rf build dist
	python setup.py sdist bdist_wheel
	twine upload dist/*

# Hub notebook targets
.PHONY: hub-build
hub-build:
	docker build --no-cache -t jupyterhub:dev --target dev .
