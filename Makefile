
check:
	PYTHONPATH=$(shell pwd) python example_consumer/manage.py test \
	   --verbosity=2 django_openid_auth

.PHONY: check
