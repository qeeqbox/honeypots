from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name='honeypots',
    author='QeeqBox',
    author_email='gigaqeeq@gmail.com',
    description=r"23 different honeypots in a single pypi package! (dns, ftp, httpproxy, http, https, imap, mysql, pop3, postgres, redis, smb, smtp, socks5, ssh, telnet, vnc, mssql, elastic, ldap, ntp, memcache, snmp, and oracle) ",
    long_description=long_description,
    version='0.36',
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
