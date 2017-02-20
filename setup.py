from setuptools import setup

setup(
    name='bananaphone',
    version='0.0.1',
    url='http://github.com/dillonhicks/bananaphone',
    license='Apache License Version 2',
    author='Dillon Hicks',
    author_email='chronodynamic@gmail.com',
    description='Simple Local File Server for Plumbing Docker Creds',
    long_description=__doc__,
    packages=['.'],
    scripts=['bin/bananaphone', 'bin/exec-with-identity'],
    include_package_data=True,
    platforms='any',
    install_requires=[
        'six',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
