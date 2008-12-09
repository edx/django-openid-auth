
check:
	PYTHONPATH=$(shell pwd) python example_consumer/manage.py test

.PHONY: check
