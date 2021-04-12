import re

def fix_ip(ip):
  # Convert /31 and /32 CIDRs to single IP
  ip = re.sub('/3[12]', '', ip)

  # Convert lower-bound CIDRs into /24 by default
  # This is assmuming that if a portion of the net
  # was seen, we want to avoid the full netblock
  ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)
  return ip

