from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name='honeypots',
    author='QeeqBox',
    author_email='gigaqeeq@gmail.com',
    description="19 honeypots in one package package for monitoring network traffic, bots activities, and username password credentials",
    long_description=long_description,
    version='0.30',
    license="AGPL-3.0",
    url="https://github.com/qeeqbox/honeypots",
    packages=['honeypots'],
    scripts=['honeypots/honeypots'],
    include_package_data=True,
    install_requires=[
        'pipenv',
        'twisted',
        'psutil',
        'psycopg2-binary',
        'dnspython',
        'requests',
        'impacket',
        'paramiko==2.7.1',
        'redis',
        'mysql-connector',
        'pycryptodome',
        'vncdotool',
        'service_identity',
        'requests[socks]',
        'pygments',
        'scapy',
        'netifaces',
        'elasticsearch',
        'pymssql',
        'ldap3'
    ],
    python_requires='>=3.5'
)
