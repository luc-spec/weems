import random
import string
import random
import glob
import os

FIXED_LISTS_DIR='./lists/*.txt'

def generate_random_url():
    if random.randint(1,10) < 2:
        return get_url_from_blocklist()
    else
        return get_dummy_url()

def get_url_from_blocklist(file_pattern, sample_size=1):
    '''
    Extract a random sample of URLs from multiple text files.
    
    Args:
        file_pattern (str): Glob pattern to match text files (e.g., 'data/*.txt')
        sample_size (int): Number of random URLs to return
    
    Returns:
        list: Random sample of URLs
    '''
    all_urls = []
    
    # Get list of all files matching the pattern
    files = glob.glob(file_pattern)
    
    # Read URLs from each file
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8') as file:
            # Read lines and strip whitespace
            file_urls = [line.strip() for line in file if line.strip()]
            all_urls.extend(file_urls)
    
    # Get random sample (or all if sample_size is larger than available URLs)
    sample_size = min(sample_size, len(all_urls))
    return random.sample(all_urls, sample_size)


def generate_dummy_url():
    '''
    Generate a plausible URL from a fixed batch of segments
    '''
    # Create lists of common TLDs, domains, and paths
    tlds = ['com', 'org', 'net', 'edu', 'io', 'co', 'app', 'dev']
    
    # Generate domain name (company or service name)
    domain_prefixes = ['app', 'my', 'the', 'get', 'try', 'use', '', 'go']
    domain_words = ['tech', 'cloud', 'data', 'stream', 'code', 'byte', 'web', 'link', 
                    'dev', 'site', 'connect', 'sync', 'flow', 'hub', 'spot', 'wave', 
                    'pulse', 'stack', 'box', 'space', 'now', 'net', 'pro']
    
    # Common URL paths
    path_segments = ['api', 'app', 'blog', 'docs', 'help', 'login', 'register', 'user',
                     'dashboard', 'account', 'profile', 'settings', 'search', 'products',
                     'services', 'about', 'contact', 'support', 'news', 'events']
    
    # Common URL parameters
    param_keys = ['id', 'user', 'page', 'limit', 'sort', 'filter', 'token', 'ref',
                  'utm_source', 'utm_medium', 'utm_campaign', 'query', 'lang', 'view']
    
    # Choose protocol
    protocol = random.choice(['http', 'https'])
    
    # Choose if we want a www prefix
    www_prefix = random.choice(['www.', ''])
    
    # Generate domain
    domain_prefix = random.choice(domain_prefixes)
    domain_word = random.choice(domain_words)
    if domain_prefix:
        domain = f'{domain_prefix}{domain_word}'
    else:
        domain = domain_word
    
    # Choose TLD
    tld = random.choice(tlds)
    
    # Decide on path length (0-4 segments)
    path_length = random.randint(0, 4)
    path = ''
    if path_length > 0:
        path_parts = []
        for _ in range(path_length):
            if random.random() < 0.7:  # 70% chance to use common path
                segment = random.choice(path_segments)
            else:  # 30% chance for random string
                segment_length = random.randint(3, 10)
                segment = ''.join(random.choices(string.ascii_lowercase, k=segment_length))
            path_parts.append(segment)
        
        path = '/' + '/'.join(path_parts)
        
        # Sometimes add a trailing slash
        if random.random() < 0.3:
            path += '/'
    
    # Decide on parameters (0-3 params)
    param_count = random.randint(0, 3)
    params = ''
    if param_count > 0:
        param_pairs = []
        for _ in range(param_count):
            # 80% chance to use common param key, 20% chance for random
            if random.random() < 0.8:
                key = random.choice(param_keys)
            else:
                key_length = random.randint(2, 8)
                key = ''.join(random.choices(string.ascii_lowercase, k=key_length))
            
            # Value could be a number, id, or string
            val_type = random.random()
            if val_type < 0.4:  # 40% chance for number
                value = str(random.randint(1, 1000))
            elif val_type < 0.7:  # 30% chance for id-like string
                value = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 12)))
            else:  # 30% chance for word-like string
                value = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 10)))
            
            param_pairs.append(f'{key}={value}')
        
        params = '?' + '&'.join(param_pairs)
    
    # Put it all together
    url = f'{protocol}://{www_prefix}{domain}.{tld}{path}{params}'
    return url

