from setuptools import setup

with open("README.rst", "r") as f:
    long_description = f.read()

setup(
    name='honeypots',
    author='QeeqBox',
    author_email='gigaqeeq@gmail.com',
    description=r"30 different honeypots in one package! (dhcp, dns, elastic, ftp, http proxy, https proxy, http, https, imap, ipp, irc, ldap, memcache, mssql, mysql, ntp, oracle, pjl, pop3, postgres, rdp, redis, sip, smb, smtp, snmp, socks5, ssh, telnet, vnc)",
    long_description=long_description,
    version='0.64',
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
        'requests==2.28.2',
        'requests[socks]==2.28.2',
        'impacket==0.9.24',
        'paramiko==3.1.0',
        'scapy==2.4.5',
        'service_identity==21.1.0',
        'netifaces==0.11.0'
    ],
    extras_require={
        'test': ['redis', 'mysql-connector', 'elasticsearch', 'pymssql', 'ldap3', 'pysnmp']
    },
    python_requires='>=3.5'
)
