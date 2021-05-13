from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name='honeypots',
    author='QeeqBox',
    author_email='gigaqeeq@gmail.com',
    description="Easy to setup honeypots!",
    long_description=long_description,
    version='0.17',
    license="AGPL-3.0",
    url="https://github.com/qeeqbox/honeypots",
    packages=['honeypots'],
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "honeypots = honeypots.__main__:main"
        ]
    },
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
        'netifaces'
    ],
    python_requires='>=3'
)
