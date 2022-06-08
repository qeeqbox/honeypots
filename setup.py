from setuptools import setup

with open("README.rst", "r") as f:
    long_description = f.read()

setup(
    name='honeypots',
    author='QeeqBox',
    author_email='gigaqeeq@gmail.com',
    description=r"23 different honeypots in a single pypi package! (dns, ftp, httpproxy, http, https, imap, mysql, pop3, postgres, redis, smb, smtp, socks5, ssh, telnet, vnc, mssql, elastic, ldap, ntp, memcache, snmp, oracle, sip and irc) ",
    long_description=long_description,
    version='0.54',
    license="AGPL-3.0",
    license_files=('LICENSE'),
    url="https://github.com/qeeqbox/honeypots",
    packages=['honeypots'],
    entry_points={
        "console_scripts": [
            'honeypots=honeypots.__main__:main_logic'
        ]
    },
    include_package_data=True,
    install_requires=[
        'twisted==21.7.0',
        'psutil==5.9.0',
        'psycopg2-binary==2.9.3',
        'pycrypto==2.6.1',
        'requests==2.27.1',
        'requests[socks]==2.27.1',
        'impacket==0.9.24',
        'paramiko==2.7.1',
        'scapy==2.4.5',
        'service_identity==21.1.0',
        'netifaces==0.11.0'
    ],
    extras_require={
        'test': ['redis', 'mysql-connector', 'elasticsearch', 'pymssql', 'ldap3', 'pysnmp']
    },
    python_requires='>=3.5'
)
