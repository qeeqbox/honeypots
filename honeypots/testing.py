import honeypots
from time import sleep
from pkg_resources import get_distribution
print("Version: ", get_distribution('honeypots').version)
for server, cls in honeypots.__dict__.items():
    if server.endswith('Server'):
        print("Start testing {}".format(server))
        temp_server = cls()
        temp_server.run_server(process=True, auto=True)
        sleep(2)
        temp_server.test_server()
        temp_server.kill_server()
        print("Done testing {}".format(server))
honeypots.clean_all()
exit()
