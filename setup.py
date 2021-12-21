from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name='honeypots',
    author='QeeqBox',
    author_email='gigaqeeq@gmail.com',
    description=r"21 different honeypots in a single PyPI package for monitoring network traffic, bots activities, and username \ password credentials. All honeypots are non-blocking and can be used as objects or called directly with the in-built auto-configure scripts. Also, they are easy to setup and customize, it takes 1-2 seconds to spin a honeypot up. The output can be logged to a postgres database, file[s], terminal or syslog for easy integration. The current honeypots are (DNS, HTTP Proxy, HTTP, HTTPS, SSH, POP3, IMAP, STMP, VNC, SMB, SOCKS5, Redis, TELNET, Postgres, MySQL, MSSQL, Elastic, LDAP, NTP and Memcache) ",
    long_description=long_description,
    version='0.35',
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
