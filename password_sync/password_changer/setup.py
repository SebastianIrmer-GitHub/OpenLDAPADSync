from setuptools import setup, Extension

module = Extension(
    'kerberosservice',
    sources=['kerberosservice.c'],
    include_dirs=['/usr/include/heimdal'],
    library_dirs=['/usr/lib/x86_64-linux-gnu/heimdal', '/usr/lib/x86_64-linux-gnu'],
    libraries=['krb5', 'com_err']
)

setup(
    name='kerberosservice',
    version='1.0',
    description='Python interface to kerberosserivce',
    ext_modules=[module]
)
