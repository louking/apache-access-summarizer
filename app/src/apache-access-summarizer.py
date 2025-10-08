# with help from gemini: https://g.co/gemini/share/83d7be7209c8

# standard
import re
from collections import Counter
from csv import DictReader, DictWriter
from io import StringIO, BytesIO
from tarfile import TarFile
from os import getenv
from glob import glob
from datetime import datetime, timedelta, timezone
from bisect import bisect_right

# pypi
from loutilities.timeu import asctime
from ipaddress import ip_address, IPv4Network
from requests import get
from requests.exceptions import RequestException

# local
from sendmail import sendmail
from version import __version__

logdtfmt = '%d/%b/%Y:%H:%M:%S %z'
logtime = asctime(logdtfmt)

class ParameterError(Exception):
    pass

def get_iso_country_codes():
    """
    Downloads and parses a CSV of ISO 3166-1 alpha-2 country codes from a public source.
    """
    url = "https://datahub.io/core/country-list/_r/-/data.csv"
    try:
        # try up to 3 times
        attempt = 0
        while True:
            attempt += 1
            try:
                response = get(url)
                response.raise_for_status()
                break
            except Exception as e:
                if attempt >= 3:
                    raise e
                else:
                    print(f"Attempt {attempt} failed, retrying...")
        
        rdr = DictReader(StringIO(response.text))
        # The ISO code is in the 'Code' column and should be converted to lowercase
        country_codes = [row['Code'].lower() for row in rdr if 'Code' in row]
        return country_codes
    except RequestException as e:
        print(f"Error downloading country list: {e}")
        return []

class CountryCidrMapper:
    """ Maps country codes to their respective CIDR IP ranges. """  
    def __init__(self, country_codes):
        self.NETWORK_MAP = []
        
        self.load_country_data(country_codes)
        
    def load_country_data(self, country_codes):
        """
        Loads CIDR networks for all available country codes from ipdeny.com.
        """
        # print("Starting to load IP blocks from ipdeny.com (This may take a minute)...")
        # try up to 3 times
        attempt = 0
        while True:
            attempt += 1
            try:
                response = get("https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz")
                response.raise_for_status()
                break
            except Exception as e:
                if attempt >= 3:
                    raise e
                else:
                    print(f"Attempt {attempt} to download country zones failed, retrying...")

        # note https://stackoverflow.com/a/14770631
        self.country_zones = TarFile.open(fileobj=BytesIO(response.content), mode="r:gz")
        # print(f'self.country_zones.getnames(): {self.country_zones.getnames()}')
        
        # retrieve country zones from tar file
        loaded_count = 0
        all_networks = []
        for code in country_codes:
            cidrs = self.download_ip_blocks(code)
            # print(f'cidrs example for {code}: {cidrs[:3]} ... {cidrs[-3:]}')  # Debug print to show some CIDRs
            if cidrs:
                try:
                    loaded_count += 1

                    # this prepares for binary search
                    for c in cidrs:
                        cidr = c.strip()
                        if cidr:
                            try:
                                network = IPv4Network(cidr, strict=False)
                                all_networks.append((int(network.network_address), network, code.upper()))
                            except Exception as e:
                                # Ignore invalid CIDR or IPv6 entries
                                pass
                
                except Exception as e:
                    # Handle cases where an entry in the .zone file might be invalid
                    print(f"Skipping network data for {code}: Invalid CIDR entry found. Error: {e}")
        
        self.NETWORK_MAP = sorted(all_networks, key=lambda x: x[0])
        
        # print(f"Successfully loaded IP blocks for {loaded_count} countries.")


    def download_ip_blocks(self, country_code):
        """
        Downloads the CIDR blocklist for a specific country from ipdeny.com.
        """
        # print(f"Retrieving IP blocks for country code: {country_code}")
        try:
            country_cidrs = self.country_zones.extractfile(f"./{country_code}.zone")
        except KeyError:
            # skipping countries not found on ipdeny.com
            # print(f"No CIDR data found for country code: {country_code}")
            return []
        
        # need to convert bytes to string before splitting
        return country_cidrs.read().decode('utf-8').strip().split('\n')
            
    def get_country_from_ip(self, ip):
        """
        Looks up the country for a given IP address using the loaded CIDR networks.
        """
        try:
            ip_obj = ip_address(ip)
            ip_int = int(ip_obj)

            # 1. Use bisect_right to find the insertion point for the IP's integer value.
            # This finds the index 'i' such that all NETWORK_MAP[j][0] for j < i are <= ip_int.
            # We only need to search the first element (index 0) of the tuples.
            network_start_addresses = [item[0] for item in self.NETWORK_MAP]
            # print(f'self.NETWORK_MAP sample: {self.NETWORK_MAP[:5]} ... {self.NETWORK_MAP[-5:]}')
            # print(f'network_start_addresses sample: {network_start_addresses[:5]} ... {network_start_addresses[-5:]}')
            # print(f'ip_int: {ip_int}')
            # print(f'len(network_start_addresses): {len(network_start_addresses)}')
            
            i = bisect_right(network_start_addresses, ip_int)
            
            # 2. The potential containing network must be at index i-1.
            # We need to check i-1 and potentially i-2 for edge cases, 
            # but one check (i-1) is usually sufficient if the data is clean.
            
            # Check the network immediately preceding the insertion point (index i-1).
            # We check two prior networks just to be extremely safe, though one should suffice.
            for j in range(max(0, i - 2), i):
                _, network, country_code = self.NETWORK_MAP[j]
                
                # 3. Check if the IP is actually contained in this network range.
                if ip_obj in network:
                    return country_code
            
        except ValueError:
            return 'INVALID IP'
        
        return 'UNKNOWN'
    
if __name__ == '__main__':
    all_country_codes = get_iso_country_codes()
    if not all_country_codes:
        raise ParameterError("Failed to retrieve country codes")
    
    # get all the country CIDR mappings
    cidr_mapper = CountryCidrMapper(all_country_codes)
    
    # https://stackoverflow.com/a/40550625/799921
    APACHE_REGEX = re.compile(r'^(?P<ip>.*?) (?P<remote_log_name>.*?) (?P<userid>.*?) \[(?P<datetime>.* .*?)\] \"(?P<request_method>.*?) (?P<path>.*?)(?P<request_version> HTTP\/.*)?\" (?P<status>.*?) (?P<length>.*?)')
    
    # how long does this take? 
    start = datetime.now()
    
    # get time window
    end_window = datetime.now(timezone.utc)
    # though for testing, use a fixed end time
    end_window_override = getenv('WINDOW_END', None)
    if end_window_override:
        end_window = logtime.asc2dt(end_window_override)
    
    period_hours = int(getenv('PERIOD_HOURS'))
    start_window = end_window - timedelta(hours=period_hours)
    
    # histogram of times
    calc_time_hist = getenv('CALC_HISTOGRAM', None)
    if calc_time_hist:
        time_hist = Counter()
    
    with StringIO() as body:
        body.write(f"Log analysis from {start_window} to {end_window} ({getenv('APP_NAME')}-{getenv('APP_VER')})\n\n")
        
        ip_counter = Counter()
        country_counter = Counter()
        unknown_counter = Counter()
        total_requests = 0

        log_files = getenv('LOG_FILES')
        for logfile in glob(f'/logs/{log_files}'):
            # print(f"Processing log file: {logfile}")
            with open(logfile, 'r') as f:
                
                for line in f:
                    match = APACHE_REGEX.match(line)
                    if match:
                        # skip line if not in time window
                        log_time = logtime.asc2dt(match.group('datetime'))
                        if log_time < start_window or log_time > end_window: continue
                        
                        # get IP, update counters and find country code
                        total_requests += 1
                        ip = match.group('ip')
                        ip_counter[ip] += 1
                        
                        country_code = cidr_mapper.get_country_from_ip(ip)
                        country_counter[country_code] += 1
                        
                        if country_code == 'UNKNOWN':
                            unknown_counter[ip] += 1
                    
                        # optional histogram of times
                        if calc_time_hist:
                            hist_time = log_time.replace(second=0, microsecond=0)
                            time_hist[hist_time] += 1

                    else:
                        body.write(f"Unmatched log line: {line.strip()}")
        
        if total_requests == 0:
            print(f"No log entries found in the specified time window {start_window} to {end_window}")

        body.write(f"Total Requests: {total_requests}\n")
        body.write("Top 10 IP Addresses:\n")
        for ip, count in ip_counter.most_common(10):
            body.write(f"{ip}: {count} requests\n")
        
        body.write("\nTop 10 Countries:\n")
        for country, count in country_counter.most_common(10):
            body.write(f"{country}: {count} requests\n")
        
        body.write("\nTop 10 IPs from unknown country:\n")
        for ip, count in unknown_counter.most_common(10):
            body.write(f"{ip}: {count} requests\n")
            
        body.write("\n" + "="*40 + "\n")
        
        # debug how long this takes
        end = datetime.now()
        duration = end - start
        body.write(f"Processing completed in {duration}\n")
        
        # send mail
        contents = body.getvalue()
        # print(contents)
        sendmail(getenv('MAIL_FROM'), getenv('MAIL_TO'), getenv('MAIL_SUBJECT'), contents)

    # send histogram if requested
    if calc_time_hist:
        with StringIO() as body:
            
            hist_csv = DictWriter(body, fieldnames=['Time', 'Requests'])
            hist_csv.writeheader()
            for t in sorted(time_hist):
                hist_csv.writerow({'Time': t.isoformat(), 'Requests': time_hist[t]})
            
            contents = body.getvalue()
            sendmail(getenv('MAIL_FROM'), getenv('MAIL_TO'), 
                     f"{getenv('HIST_SUBJECT')} - {start_window} to {end_window}", 
                     f"{getenv('HIST_SUBJECT')} - {start_window} to {end_window}", 
                     files=[('attachment', (f'access_histogram_{end_window.isoformat()}.csv', contents))])