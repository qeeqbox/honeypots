import honeypots
from time import sleep
from pkg_resources import get_distribution
honeypots.clean_all()
print("Version: ", get_distribution('honeypots').version)
for server, cls in honeypots.__dict__.items():
    if server.endswith('Server'):
        temp_server = cls(options="capture_commands")
        temp_server.run_server(process=True, auto=True)
        sleep(2)
        temp_server.test_server()
        sleep(2)
        temp_server.kill_server()
honeypots.clean_all()
exit()
