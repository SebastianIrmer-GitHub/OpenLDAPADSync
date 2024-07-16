from setuptools import setup, Extension

module = Extension(
    'kadmin',
    sources=['kadmin_interface_wrapper.c'],
    include_dirs=['/usr/include/heimdal'],
    library_dirs=['/usr/lib/x86_64-linux-gnu/heimdal', '/usr/lib/x86_64-linux-gnu'],
    libraries=['kadm5clnt', 'krb5', 'asn1', 'com_err', 'roken'],
    extra_objects=['libkadmin_interface.a']  # Link your static library
)

setup(
    name='kadmin',
    version='1.0',
    description='Python interface to kadmin',
    ext_modules=[module]
)
