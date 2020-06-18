jupyterhub_chameleon/service/cull_idle_servers.py:
	curl -L -o $@ \
		https://raw.githubusercontent.com/jupyterhub/jupyterhub/master/examples/cull-idle/cull_idle_servers.py

.PHONY: publish
publish: jupyterhub_chameleon/service/cull_idle_servers.py
	@ rm -rf build dist
	python setup.py sdist bdist_wheel
	twine upload dist/*
