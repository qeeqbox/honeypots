__G__ = "(G)bd249ce4"

from argparse import ArgumentParser


def server_arguments():
    _server_parser = ArgumentParser(prog="Server")
    _server_parsergroupdeq = _server_parser.add_argument_group('Initialize Server')
    _server_parsergroupdeq.add_argument('--ip', type=str, help="Change server ip, current is 0.0.0.0", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--port', type=int, help="Change port", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--username', type=str, help="Change username", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--password', type=str, help="Change password", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--resolver_addresses', type=str, help="Change resolver address", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--domain', type=str, help="A domain to test", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--mocking', type=str, help="Random banner", required=False)
    _server_parsergroupdes = _server_parser.add_argument_group('Sinffer options')
    _server_parsergroupdes.add_argument('--filter', type=str, help="setup the Sinffer filter", required=False)
    _server_parsergroupdes.add_argument('--interface', type=str, help="sinffer interface E.g eth0", required=False)
    _server_parsergroupdef = _server_parser.add_argument_group('Initialize Loging')
    _server_parsergroupdef.add_argument('--logs', type=str, help="db, terminal or all ", required=False)
    _server_parsergroupdea = _server_parser.add_argument_group('Auto Configuration')
    _server_parsergroupdea.add_argument('--docker', action='store_true', help="Run project in docker", required=False)
    _server_parsergroupdea.add_argument('--aws', action='store_true', help="Run project in aws", required=False)
    _server_parsergroupdea.add_argument('--test', action='store_true', help="Test current server", required=False)
    _server_parsergroupdea.add_argument('--custom', action='store_true', help="Run custom server", required=False)
    return _server_parser.parse_args()
