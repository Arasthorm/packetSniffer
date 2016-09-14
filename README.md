# packetSniffer
A simple packet sniffer made in python that captures network packets that your computer sends and receives. The program shows different packet fields from layer 2 to layer 4 of OSI. By using a database from MaxMind the program translates IP addresses to cities and countries.

## How to run:

Since the program uses MaxMind api, you have to download the python extension api (https://github.com/maxmind/geoip-api-python) and the GeoLiteCity database (http://dev.maxmind.com/geoip/legacy/geolite/). After you get all this just run python packetSniffer.py and prepare yourself to receive loads of traffic if you are connected to the Internet.


