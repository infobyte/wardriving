# Wardriving

Here you can find all the data about the Wardriving Workshop from [Ekoparty 2017](http://ekoparty.org).

## Faraday Plugins

The files starting with `import_` are all modules to be used with the Faraday Plugin. In order to run them, download and copy to you `{faraday_installation}/bin/`. For more info on the Faraday Plugin read the [official documentation](https://github.com/infobyte/faraday/wiki/Faraday-Plugin).

### import_dns_pcap.py

The file import_dns_pcap.py will read all packets saved from Open WiFi networks. It will create vulnerabilities for non-encrypted cookies or authorization data.

### import_wigle.py

The file import_wigle.py will create a vulnerability with Informational severity and attach a map as evidence. This plugin uses the Android SQLite database as input.

### import_wardriving_pcap.py

The file import_wardriving_pcap.py creates objects in Faraday according to the security settings of the networks found in a PCAP. Users will be able to see statistics in the Faraday Dashboard including how many networks are using wpa, wpa2, wep and open. It will create vulnerabilities for open and wep. If any of the PCAP files contain a 4way handshake it will also create a vuln with the keys as evidence.
Also, a vulnerability containing the top 10 probe requests found and an XLS file with the vendor frequency will be added.

## How to use the plugin?

Move the .py plugins to the bin directory of faraday. 
cd into bin directory to execute fplugin as detailed below.

### import_dns_pcap.py

/fplugin import_dns_pcap wardriving.cap -w eko_wardriving

### import_wigle.py

First copy the .sqlite in your smartphone to your computer. Then import .sqlite to eko_wardiring using the command:

/fplugin import_wigle /home/lcubo/wigle/wiglewifi.sqlite -w eko_wardriving

### import_wardriving_pcap.py

If you want to load wardriving statistics from a pcap file to the eko_wardring workspace use the following command:

./fplugin import_wardriving_pcap wardriving.cap -w eko_wardriving
