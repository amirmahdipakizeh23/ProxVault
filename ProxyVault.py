import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, END
import ttkbootstrap as bs
from ttkbootstrap.constants import 
import requests
import threading
import queue
import time
from urllib.parse import urlparse
import concurrent.futures
import csv
import json
import re
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import configparser
import ipaddress
import random
import socket
from datetime import datetime, timedelta
from tenacity import retry, stop_after_attempt, wait_exponential

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import numpy as np
from collections import defaultdict

DEFAULT_TEST_URL = 'httpshttpbin.orgget'
TEST_URLS = [
    'httpshttpbin.orgget',
    'httphttpbin.orgget',
    'httpsapi.ipify.orgformat=json',
    'httpapi.ipify.orgformat=json',
    'httpswww.google.com',
    'httpwww.google.com',
]

DOWNLOAD_TEST_URLS = [
    'httpipv4.download.thinkbroadband.com1MB.zip',
    'httphttpbin.orgbytes1000000',
    'httpsspeed.cloudflare.com__downbytes=1000000',
    'httpshttpbin.orgbytes1000000',
]
GEOLOCATION_API_URL = 'httpip-api.comjson'
PROXY_SCRAPE_BASE_URL = 'httpsraw.githubusercontent.comSoliSpiritproxy-listmain'
APP_VERSION = '4.0'
APP_NAME = 'ProxVault'
AUTHOR_NAME = 'Amir Mahdi Pakizeh'

class ConfigManager
    def __init__(self, config_file='proxy_checker_config.ini')
        self.config_file = Path(config_file)
        self.config = configparser.ConfigParser()
        self._load_config()
    
    def _load_config(self)
        if self.config_file.exists()
            self.config.read(self.config_file)
        else
            self._create_default_config()
    
    def _create_default_config(self)
        self.config['General'] = {
            'timeout' '10',
            'max_threads' '50',
            'test_url' DEFAULT_TEST_URL,
            'download_test_url' DOWNLOAD_TEST_URLS[0],
            'geolocation_api_url' GEOLOCATION_API_URL
        }
        self.config['GUI'] = {
            'theme' 'darkly',
            'window_size' '1200x800',
            'language' 'en'
        }
        self.config['ProxyScraping'] = {
            'base_url' 'httpsraw.githubusercontent.comSoliSpiritproxy-listmain'
        }
        self.config['About'] = {
            'version' APP_VERSION,
            'author' AUTHOR_NAME
        }
        self.config['Filtering'] = {
            'min_score' '0',
            'max_latency' '5.0',
            'min_speed' '0.1',
            'anonymity_levels' 'Elite,Anonymous,Transparent',
            'protocols' 'HTTP,HTTPS,SOCKS4,SOCKS5'
        }
        self.config['Scoring'] = {
            'latency_weight' '0.30',
            'speed_weight' '0.30',
            'anonymity_weight' '0.15',
            'consistency_weight' '0.10',
            'geo_weight' '0.05',
            'reliability_weight' '0.10'
        }
        self.save_config()
    
    def save_config(self)
        with open(self.config_file, 'w') as f
            self.config.write(f)
    
    def get(self, section, key, fallback=None)
        try
            return self.config.get(section, key)
        except Exception
            return fallback
    
    def set(self, section, key, value)
        if section not in self.config
            self.config.add_section(section)
        self.config.set(section, key, value)
        self.save_config()

config_manager = ConfigManager()

class ProxyCache
    def __init__(self, cache_file='proxy_cache.json', expiry_hours=0.083)
        self.cache_file = Path(cache_file)
        self.expiry = timedelta(hours=expiry_hours)
        self.cache = self._load_cache()
        self.history = defaultdict(list)
    
    def _load_cache(self)
        if self.cache_file.exists()
            try
                with open(self.cache_file, 'r') as f
                    return json.load(f)
            except Exception
                return {}
        return {}
    
    def _save_cache(self)
        try
            with open(self.cache_file, 'w') as f
                json.dump(self.cache, f)
        except Exception
            pass
    
    def get(self, proxy)
        if proxy in self.cache
            cached_time = datetime.fromisoformat(self.cache[proxy]['timestamp'])
            if datetime.now() - cached_time  self.expiry
                return self.cache[proxy]['result']
        return None
    
    def set(self, proxy, result)
        self.cache[proxy] = {
            'result' result,
            'timestamp' datetime.now().isoformat()
        }

        self.history[proxy].append({
            'timestamp' datetime.now().isoformat(),
            'latency' result.get('latency', 'NA'),
            'speed' result.get('speed', 'NA'),
            'status' result.get('status', 'unknown')
        })

        if len(self.history[proxy])  10
            self.history[proxy] = self.history[proxy][-10]
        self._save_cache()
    
    def clear(self)
        self.cache = {}
        self.history = defaultdict(list)
        self._save_cache()
    
    def get_history(self, proxy)
        Get historical performance data for a proxy.
        return self.history.get(proxy, [])

proxy_cache = ProxyCache()

class HeaderManager
    def __init__(self)
        self.user_agents = [
            'Mozilla5.0 (Windows NT 10.0; Win64; x64) AppleWebKit537.36 (KHTML, like Gecko) Chrome91.0.4472.124 Safari537.36',
            'Mozilla5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit537.36 (KHTML, like Gecko) Chrome91.0.4472.114 Safari537.36',
            'Mozilla5.0 (Windows NT 10.0; Win64; x64; rv89.0) Gecko20100101 Firefox89.0',
            'Mozilla5.0 (X11; Linux x86_64) AppleWebKit537.36 (KHTML, like Gecko) Chrome92.0.4515.107 Safari537.36'
        ]
        self.headers = {
            'Accept' 'texthtml,applicationxhtml+xml,applicationxml;q=0.9,imagewebp,;q=0.8',
            'Accept-Language' 'en-US,en;q=0.5',
            'Accept-Encoding' 'gzip, deflate',
            'DNT' '1',
            'Connection' 'keep-alive',
            'Upgrade-Insecure-Requests' '1'
        }
    
    def get_headers(self)
        headers = self.headers.copy()
        headers['User-Agent'] = random.choice(self.user_agents)
        return headers

header_manager = HeaderManager()

def setup_logging()
    log_file = 'proxy_checker.log'
    logger = logging.getLogger('proxy_checker')
    logger.setLevel(logging.INFO)
    

    for handler in logger.handlers[]
        logger.removeHandler(handler)
    

    file_handler = RotatingFileHandler(
        log_file, maxBytes=510241024, backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

def validate_proxy(proxy)
    Validate proxy format and check for privatereserved IP ranges.
    try

        if '' in proxy
            proxy = proxy.split('')[1]
        

        if not re.match(r'^(d{1,3}.){3}d{1,3}d{1,5}$', re.sub(r'^[^@]+@', '', proxy))
            return False
        

        proxy_clean = re.sub(r'^[^@]+@', '', proxy)
        ip, port = proxy_clean.split('')
        

        ipaddress.ip_address(ip)
        

        port_num = int(port)
        if not (1 = port_num = 65535)
            return False
        

        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
            return False
        
        return True
    except Exception as e
        logger.warning(fProxy validation error for {proxy} {e})
        return False

def verify_proxy_connection(proxy, timeout=5)
    Verify that a proxy can actually establish a connection.
    try

        if '' in proxy
            proxy = proxy.split('')[1]
        

        ip, port = proxy.split('')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        
        return result == 0
    except Exception as e
        logger.warning(fProxy connection verification failed for {proxy} {e})
        return False

def calculate_proxy_score(result, historical_results=None, target_countries=None)
    Calculate a quality score for a proxy based on its performance metrics.
    score = 0
    max_score = 100
    
    try

        latency_weight = float(config_manager.get('Scoring', 'latency_weight'))
        speed_weight = float(config_manager.get('Scoring', 'speed_weight'))
        anonymity_weight = float(config_manager.get('Scoring', 'anonymity_weight'))
        consistency_weight = float(config_manager.get('Scoring', 'consistency_weight'))
        geo_weight = float(config_manager.get('Scoring', 'geo_weight'))
        reliability_weight = float(config_manager.get('Scoring', 'reliability_weight', '0.10'))
        

        latency = float(result['latency'])
        if latency  0.2
            latency_score = 100
        elif latency  0.5
            latency_score = 85
        elif latency  1.0
            latency_score = 70
        elif latency  2.0
            latency_score = 50
        elif latency  5.0
            latency_score = 30
        else
            latency_score = 10
        
        score += latency_score  latency_weight
        

        if result['speed'] != NA
            speed = float(result['speed'].split(' ')[0])
            if speed  10.0
                speed_score = 100
            elif speed  5.0
                speed_score = 85
            elif speed  2.0
                speed_score = 70
            elif speed  1.0
                speed_score = 50
            elif speed  0.5
                speed_score = 30
            else
                speed_score = 10
            
            score += speed_score  speed_weight
        

        anonymity_scores = {'Elite' 100, 'Anonymous' 70, 'Transparent' 30}
        anonymity_score = anonymity_scores.get(result['anonymity'], 0)
        score += anonymity_score  anonymity_weight
        

        if 'reliability' in result
            reliability_parts = result['reliability'].split('')
            if len(reliability_parts) == 2
                successful = int(reliability_parts[0])
                total = int(reliability_parts[1])
                if total  0
                    reliability_score = (successful  total)  100
                    score += reliability_score  reliability_weight
        

        if historical_results
            consistency_score = calculate_consistency_score(result['proxy'], historical_results)
            score += consistency_score  consistency_weight
        

        if target_countries
            geo_score = calculate_geo_relevance(result['country'], target_countries)
            score += geo_score  geo_weight
        
        return min(score, max_score)
    except Exception as e
        logger.warning(fError calculating proxy score {e})
        return 0

def calculate_consistency_score(proxy, historical_results)
    Calculate a consistency score based on historical performance.
    if len(historical_results)  3
        return 50
    

    latencies = []
    for r in historical_results
        try
            latencies.append(float(r['latency']))
        except (ValueError, TypeError)
            continue
    
    if not latencies
        return 50
    
    avg_latency = sum(latencies)  len(latencies)
    variance = sum((x - avg_latency)  2 for x in latencies)  len(latencies)
    std_dev = variance  0.5
    

    if std_dev  0.1
        return 100
    elif std_dev  0.5
        return 80
    elif std_dev  1.0
        return 60
    else
        return 30

def calculate_geo_relevance(proxy_country, target_countries)
    Calculate geographical relevance score.
    if not target_countries
        return 50
    
    if proxy_country in target_countries
        return 100
    else
        return 30

def calculate_protocol_score(proxy_type)
    Calculate score based on proxy protocol.
    protocol_scores = {
        'HTTPS' 100,
        'HTTP' 80,
        'SOCKS5' 90,
        'SOCKS4' 70
    }
    return protocol_scores.get(proxy_type.upper(), 50)

@retry(stop=stop_after_attempt(1), wait=wait_exponential(multiplier=1, min=2, max=4))
def check_proxy_with_retry(proxy, real_ip, timeout, test_url, headers, test_speed=False)
    Check proxy with retry logic and multiple test URLs.
    if not validate_proxy(proxy)
        raise ValueError(fInvalid proxy format {proxy})
    

    original_proxy = proxy
    match = re.match(r'^(httpssocks4socks5)', proxy)
    if match
        proxy_type = match.group(1).upper()
    else
        proxy_type = HTTPS
        proxy = f'http{proxy}'
    
    proxy_protocols = {'http' proxy, 'https' proxy}
    proxy_ip = urlparse(proxy).hostname
    

    successful_tests = 0
    total_tests = 0
    total_latency = 0
    saved_httpbin_data = None

    for url in TEST_URLS
        try
            start_time = time.time()
            response = requests.get(url, proxies=proxy_protocols, timeout=timeout, headers=headers)
            latency = time.time() - start_time
            response.raise_for_status()
            total_tests += 1

            content_type = response.headers.get('Content-Type', '')
            if 'json' in content_type
                try
                    data = response.json()
                    if isinstance(data, dict) and len(data)  0
                        successful_tests += 1
                        total_latency += latency

                        if 'httpbin' in url and saved_httpbin_data is None
                            saved_httpbin_data = data

                        if 'origin' in data and real_ip and real_ip in str(data['origin'])
                            raise ValueError(fIP leak detected proxy returned real IP {real_ip})
                except ValueError as ve
                    if 'IP leak' in str(ve)
                        raise
                    continue
            else
                if response.status_code == 200
                    successful_tests += 1
                    total_latency += latency
        except ValueError
            raise
        except Exception as e

            err_type = SSLHTTPS not supported if SSL in str(e) or ssl in str(e) else str(e)[80]
            logger.debug(fTest failed for {proxy} with {url} {err_type})
            continue

    if successful_tests  2
        raise ValueError(fProxy {proxy} failed reliability tests ({successful_tests}{total_tests} successful))

    avg_latency = total_latency  successful_tests

    try
        if saved_httpbin_data is None

            response = requests.get(DEFAULT_TEST_URL, proxies=proxy_protocols, timeout=timeout, headers=headers)
            response.raise_for_status()
            saved_httpbin_data = response.json()

        resp_headers = saved_httpbin_data.get('headers', {})

        anonymity = 'Elite'
        if real_ip and any(real_ip in str(v) for v in resp_headers.values())
            anonymity = 'Transparent'
        elif any(h in resp_headers for h in ['Via', 'X-Forwarded-For'])
            anonymity = 'Anonymous'

        geo_info = NA
        try
            geo_response = requests.get(f{GEOLOCATION_API_URL}{proxy_ip}fields=country, timeout=2)
            if geo_response.status_code == 200
                geo_info = geo_response.json().get('country', 'NA')
        except Exception as e
            logger.warning(fError getting geolocation for {proxy_ip} {e})

        download_speed = NA
        if test_speed
            for test_url_dl in DOWNLOAD_TEST_URLS
                try
                    start_download_time = time.time()
                    with requests.get(
                        test_url_dl,
                        proxies=proxy_protocols,
                        timeout=15,
                        stream=True,
                        headers=headers
                    ) as dl_resp
                        dl_resp.raise_for_status()
                        total_size = 0
                        for chunk in dl_resp.iter_content(chunk_size=8192)
                            total_size += len(chunk)

                            if total_size = 1_000_000
                                break
                        download_duration = time.time() - start_download_time
                        if download_duration  0 and total_size  0
                            speed_mbps = (total_size  8)  (download_duration  1_000_000)
                            download_speed = f{speed_mbps.2f} Mbps
                            break
                except Exception as e
                    logger.debug(fSpeed test URL {test_url_dl} failed for {proxy} {e})
                    continue
            if download_speed == NA
                logger.warning(fAll speed test URLs failed for {proxy})

        result = {
            'status' 'working',
            'proxy' original_proxy,
            'latency' f{avg_latency.2f},
            'anonymity' anonymity,
            'country' geo_info,
            'speed' download_speed,
            'type' proxy_type,
            'reliability' f{successful_tests}{total_tests}
        }

        historical_results = proxy_cache.get_history(original_proxy)
        result['score'] = calculate_proxy_score(result, historical_results)

        return result
    except Exception as e
        logger.warning(fError checking proxy {proxy} {e})
        raise

def check_proxy(proxy, real_ip, timeout, q, stop_event, test_url, test_speed=False)
    Enhanced proxy checking function with caching and retry logic.
    if stop_event.is_set()
        return
    if test_speed
        logger.debug(fSpeed test ENABLED for {proxy})
    

    cached_result = proxy_cache.get(proxy)
    if cached_result
        cached_has_speed = cached_result.get('speed', 'NA') != 'NA'
        if not test_speed or cached_has_speed
            q.put(cached_result)
            return

    
    try
        headers = header_manager.get_headers()

        if proxy.startswith(('socks4', 'socks5'))
            try
                import socks
            except ImportError
                logger.warning(fSkipping SOCKS proxy {proxy} — pysocks not installed (pip install pysocks))
                q.put({'status' 'bad', 'proxy' proxy})
                return
        result = check_proxy_with_retry(proxy, real_ip, timeout, test_url, headers, test_speed=test_speed)
        

        if result.get('status') == 'working'
            proxy_cache.set(proxy, result)
        
        if not stop_event.is_set()
            q.put(result)
    except Exception as e

        cause = str(e)
        if 'RetryError' in cause and 'raised' in cause
            import re as _re
            inner = _re.search(r'raised (w+Error[^]])', cause)
            cause = inner.group(1) if inner else cause
        logger.warning(fProxy {proxy} failed {cause})
        if not stop_event.is_set()
            q.put({'status' 'bad', 'proxy' proxy})

class ProgressTracker
    Track progress of proxy checking.
    def __init__(self, total_proxies)
        self.total = total_proxies
        self.checked = 0
        self.working = 0
        self.failed = 0
        self.start_time = time.time()
    
    def update(self, status)
        self.checked += 1
        if status == 'working'
            self.working += 1
        else
            self.failed += 1
        return self.get_progress()
    
    def get_progress(self)
        elapsed = time.time() - self.start_time
        remaining = (elapsed  self.checked)  (self.total - self.checked) if self.checked  0 else 0
        
        return {
            'total' self.total,
            'checked' self.checked,
            'working' self.working,
            'failed' self.failed,
            'progress' self.checked  self.total  100 if self.total  0 else 0,
            'elapsed' elapsed,
            'remaining' remaining,
            'rate' self.checked  elapsed if elapsed  0 else 0
        }

def _anonymity_tag(anonymity)
    Return treeview tag name for a given anonymity level.
    return {Elite elite, Anonymous anonymous, Transparent transparent}.get(anonymity, elite)

class ProxyCheckerApp
    def __init__(self, root)
        self.root = root

        self.root.title(f{APP_NAME} v{APP_VERSION} - {AUTHOR_NAME})

        window_size = config_manager.get('GUI', 'window_size')
        self.root.geometry(window_size)

        try

            from ctypes import windll

            windll.dwmapi.DwmSetWindowAttribute(
                self.root.winfo_id(), 
                20,
                2,
                4
            )
        except Exception as e
            logger.warning(fCould not set dark mode for title bar {e})

        try
            self.root.iconbitmap('proxy_icon.ico')
        except Exception
            pass
            
        self.working_proxies = []
        self.stop_event = threading.Event()
        self.checker_thread = None
        self.progress_tracker = None
        self.executor = None
        self.is_checking = False
        self.target_countries = []
        

        self.working_count = 0
        self.failed_count = 0
        self.q = queue.Queue()
        self._spinner_running = False
        

        self.create_menu()
        

        self.create_main_frames()
        

        self.create_input_widgets()
        

        self.create_settings_widgets()
        

        self.create_results_widgets()
        

        self.create_status_bar()

        self.update_status_bar_info()
    
    def create_menu(self)
        Create application menu bar.
        menubar = tk.Menu(self.root)
        

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label=Import Proxies, command=self.import_from_file)
        file_menu.add_command(label=Export Results, command=self.export_results, state=DISABLED)
        file_menu.add_command(label=Generate Report, command=self.generate_report, state=DISABLED)
        file_menu.add_separator()
        file_menu.add_command(label=Exit, command=self.root.quit)
        menubar.add_cascade(label=File, menu=file_menu)
        

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label=Clear Cache, command=self.clear_cache)
        tools_menu.add_command(label=View Cache Stats, command=self.view_cache_stats)
        tools_menu.add_command(label=View Analytics, command=self.show_analytics)
        tools_menu.add_separator()
        tools_menu.add_command(label=Save Settings, command=self.save_settings)
        menubar.add_cascade(label=Tools, menu=tools_menu)
        

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=User Guide, command=self.show_user_guide)
        help_menu.add_separator()
        help_menu.add_command(label=About ProxVault, command=self.show_about_dialog)
        menubar.add_cascade(label=Help, menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_main_frames(self)
        Create main application frames.
        main_frame = ttk.Frame(self.root, padding=(12, 8))
        main_frame.pack(fill=BOTH, expand=YES)

        header = tk.Frame(main_frame, bg=#0d1117, height=72)
        header.pack(fill=X, pady=(0, 0))
        header.pack_propagate(False)

        tk.Frame(header, bg=#4a90d9, width=4).pack(side=LEFT, fill=Y)

        left_block = tk.Frame(header, bg=#0d1117)
        left_block.pack(side=LEFT, padx=14, pady=10)

        icon_canvas = tk.Canvas(left_block, width=44, height=44,
                                bg=#0d1117, highlightthickness=0)
        icon_canvas.pack(side=LEFT, padx=(0, 12))

        icon_canvas.create_oval(2, 2, 42, 42, fill=#141c2e, outline=#4a90d9, width=2)

        icon_canvas.create_oval(10, 10, 34, 34, fill=#1a2a4a, outline=#2d6bbd, width=1)

        icon_canvas.create_rectangle(16, 24, 28, 34, fill=#4a90d9, outline=)

        icon_canvas.create_arc(16, 14, 28, 28, start=0, extent=180,
                               style=arc, outline=#4a90d9, width=2)

        icon_canvas.create_oval(20, 27, 24, 31, fill=#0d1117, outline=)

        title_block = tk.Frame(left_block, bg=#0d1117)
        title_block.pack(side=LEFT)
        tk.Label(title_block, text=APP_NAME, bg=#0d1117, fg=#ffffff,
                 font=(Helvetica, 18, bold)).pack(anchor=W)
        tk.Label(title_block,
                 text=fv{APP_VERSION}   •   Proxy Intelligence Platform   •   by {AUTHOR_NAME},
                 bg=#0d1117, fg=#4a90d9,
                 font=(Helvetica, 8)).pack(anchor=W)

        right_block = tk.Frame(header, bg=#0d1117)
        right_block.pack(side=RIGHT, padx=16)
        top_right = tk.Frame(right_block, bg=#0d1117)
        top_right.pack(anchor=E)

        self._spinner_running = False
        self._spinner_label = tk.Label(top_right, text=, bg=#0d1117, fg=#4a90d9,
                                       font=(Helvetica, 14))
        self._spinner_label.pack(side=LEFT, padx=(0, 8))
        self.clock_label = tk.Label(top_right, bg=#0d1117, fg=#8b949e,
                                    font=(Helvetica, 9))
        self.clock_label.pack(side=LEFT)
        tk.Label(right_block, text=Help → User Guide for feature explanations,
                 bg=#0d1117, fg=#3a5a7f, font=(Helvetica, 7, italic)).pack(anchor=E)
        self._tick_clock()

        tk.Frame(main_frame, bg=#4a90d9, height=1).pack(fill=X)
        tk.Frame(main_frame, bg=#1a2a3a, height=1).pack(fill=X, pady=(0, 10))

        stats_frame = tk.Frame(main_frame, bg=#1e1e2e)
        stats_frame.pack(fill=X, pady=(0, 10))

        self._stat_labels = {}
        card_defs = [
            (total,   TOTAL,   #4a90d9, 0),
            (working, WORKING, #28a745, 0),
            (dead,    DEAD,    #dc3545, 0),
            (rate,    RATE,    #fd7e14, 0s),
            (elapsed, ELAPSED, #6f42c1, 0s),
            (eta,     ETA,     #20c997, —),
        ]
        for key, label, color, default in card_defs
            card = tk.Frame(stats_frame, bg=#252535, bd=0,
                            highlightbackground=color, highlightthickness=1)
            card.pack(side=LEFT, expand=YES, fill=X, padx=4, pady=4)
            tk.Label(card, text=label, bg=#252535, fg=color,
                     font=(Helvetica, 7, bold)).pack(pady=(6, 0))
            val_lbl = tk.Label(card, text=default, bg=#252535, fg=#ffffff,
                               font=(Helvetica, 18, bold))
            val_lbl.pack(pady=(0, 6))
            self._stat_labels[key] = val_lbl

        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=X, expand=NO)

        input_frame = ttk.LabelFrame(top_frame, text=  Input Proxies  , padding=10)
        input_frame.pack(fill=BOTH, expand=YES, side=LEFT, padx=(0, 6))

        settings_frame = ttk.LabelFrame(top_frame, text=  Settings & Actions  , padding=10)
        settings_frame.pack(fill=Y, side=RIGHT)

        results_outer = ttk.LabelFrame(main_frame, text=  Results  , padding=10)
        results_outer.pack(fill=BOTH, expand=YES, pady=(10, 0))

        results_frame = tk.Frame(results_outer, bg=#0d1117)
        results_frame.pack(fill=BOTH, expand=YES)

        self.main_frame = main_frame
        self.input_frame = input_frame
        self.settings_frame = settings_frame
        self.results_frame = results_frame

    def _tick_clock(self)
        Update the live clock in the header every second.
        now = datetime.now().strftime(%A, %d %b %Y   %H%M%S)
        self.clock_label.config(text=now)
        self.root.after(1000, self._tick_clock)

    _SPINNER_FRAMES = [⠋,⠙,⠹,⠸,⠼,⠴,⠦,⠧,⠇,⠏]

    def _start_spinner(self)
        self._spinner_idx = 0
        self._spinner_running = True
        self._spin()

    def _spin(self)
        if not self._spinner_running
            return
        frame = self._SPINNER_FRAMES[self._spinner_idx % len(self._SPINNER_FRAMES)]
        try
            self._spinner_label.config(text=frame)
        except Exception
            return
        self._spinner_idx += 1
        self.root.after(80, self._spin)

    def _stop_spinner(self)
        self._spinner_running = False
        try
            self._spinner_label.config(text=✔)
            self.root.after(2000, lambda self._spinner_label.config(text=))
        except Exception
            pass

    def _update_stat_cards(self)
        Push current numbers into the stats cards.
        if self.progress_tracker
            p = self.progress_tracker.get_progress()
            self._stat_labels[total].config(text=str(p[total]))
            self._stat_labels[working].config(text=str(p[working]))
            self._stat_labels[dead].config(text=str(p[failed]))
            self._stat_labels[rate].config(text=f{p['rate'].1f}s)
            self._stat_labels[elapsed].config(text=f{int(p['elapsed'])}s)
            eta = p[remaining]
            self._stat_labels[eta].config(text=f{int(eta)}s if eta  0 else —)
        else
            self._stat_labels[total].config(text=0)
            self._stat_labels[working].config(text=str(self.working_count))
            self._stat_labels[dead].config(text=str(self.failed_count))
            self._stat_labels[rate].config(text=0s)
            self._stat_labels[elapsed].config(text=0s)
            self._stat_labels[eta].config(text=—)
    
    def create_input_widgets(self)
        Create widgets for input frame.

        self.proxy_text = scrolledtext.ScrolledText(
            self.input_frame, width=45, height=10, wrap=tk.WORD,
            font=(Consolas, 10), relief=flat, bd=0,
            bg=#1e1e2e, fg=#e0e0e0, insertbackground=#4a90d9,
            selectbackground=#375a7f
        )
        self.proxy_text.pack(fill=BOTH, expand=YES, pady=(0, 6))

        ttk.Separator(self.input_frame, orient=HORIZONTAL).pack(fill=X, pady=(0, 6))

        scrape_frame = ttk.Frame(self.input_frame)
        scrape_frame.pack(fill=X, pady=(0, 4))
        ttk.Label(scrape_frame, text=Protocol, font=(Helvetica, 9)).pack(side=LEFT, padx=(0, 4))
        self.scrape_protocol_var = tk.StringVar(value='http')
        protocol_choices = ['http', 'https', 'socks4', 'socks5']
        self.protocol_combobox = ttk.Combobox(
            scrape_frame, textvariable=self.scrape_protocol_var,
            values=protocol_choices, state=readonly, width=9,
            font=(Helvetica, 9)
        )
        self.protocol_combobox.pack(side=LEFT, padx=(0, 6))
        self.scrape_button = ttk.Button(scrape_frame, text=⬇  Scrape Proxies,
                                        command=self.start_scraping, style=info.TButton)
        self.scrape_button.pack(side=LEFT, fill=X, expand=True)

        action_row = ttk.Frame(self.input_frame)
        action_row.pack(fill=X, pady=(0, 4))
        ttk.Button(action_row, text=📂  Import from File,
                   command=self.import_from_file, style=primary.TButton
                   ).pack(side=LEFT, fill=X, expand=True, padx=(0, 4))
        ttk.Button(action_row, text=🗑  Clear Cache,
                   command=self.clear_cache
                   ).pack(side=LEFT, fill=X, expand=True, padx=(0, 4))
        ttk.Button(action_row, text=📊  Cache Stats,
                   command=self.view_cache_stats
                   ).pack(side=LEFT, fill=X, expand=True)
    
    def create_settings_widgets(self)
        Create widgets for settings frame.
        SF = self.settings_frame
        LF = (Helvetica, 9)
        EF = (Consolas, 9)
        PAD = dict(padx=6, pady=4)

        def _lbl(text, row, col=0, span=2, kw)
            ttk.Label(SF, text=text, font=LF).grid(
                row=row, column=col, columnspan=span, sticky=W, padx=6, pady=(8,1))

        _lbl(🌐  Test URL, 0)
        self.test_url_entry = ttk.Entry(SF, width=32, font=EF)
        self.test_url_entry.insert(END, config_manager.get('General', 'test_url'))
        self.test_url_entry.grid(row=1, column=0, columnspan=2, PAD, sticky=ew)

        _lbl(⏱  Timeout (s), 2, col=0, span=1)
        _lbl(🔀  Threads, 2, col=1, span=1)
        self.timeout_spinbox = ttk.Spinbox(SF, from_=1, to=60, width=8, font=LF)
        self.timeout_spinbox.set(config_manager.get('General', 'timeout'))
        self.timeout_spinbox.grid(row=3, column=0, padx=6, pady=4, sticky=ew)
        self.threads_spinbox = ttk.Spinbox(SF, from_=1, to=150, width=8, font=LF)
        self.threads_spinbox.set(config_manager.get('General', 'max_threads'))
        self.threads_spinbox.grid(row=3, column=1, padx=6, pady=4, sticky=ew)

        _lbl(🔗  Scrape Base URL, 4)
        self.scrape_base_url_entry = ttk.Entry(SF, width=32, font=EF)
        self.scrape_base_url_entry.insert(END, config_manager.get('ProxyScraping', 'base_url'))
        self.scrape_base_url_entry.grid(row=5, column=0, columnspan=2, PAD, sticky=ew)

        _lbl(🌍  Target Countries (comma-separated), 6)
        self.target_countries_entry = ttk.Entry(SF, width=32, font=EF)
        self.target_countries_entry.grid(row=7, column=0, columnspan=2, PAD, sticky=ew)

        ttk.Separator(SF, orient=HORIZONTAL).grid(row=8, column=0, columnspan=2, sticky=ew, pady=8)

        self.speed_test_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(SF, text=⚡  Enable Speed Test (slower),
                        variable=self.speed_test_var
                        ).grid(row=9, column=0, columnspan=2, sticky=w, padx=6, pady=(0, 6))

        self.start_button = ttk.Button(SF, text=▶   START CHECKING,
                                       command=self.start_checking, style='success.TButton')
        self.start_button.grid(row=10, column=0, columnspan=2, padx=6, pady=(0,4), sticky=ew, ipady=6)
        self.stop_button = ttk.Button(SF, text=■   STOP,
                                      command=self.stop_checking, style='danger.TButton', state=DISABLED)
        self.stop_button.grid(row=11, column=0, columnspan=2, padx=6, pady=(0,4), sticky=ew, ipady=4)

        ttk.Separator(SF, orient=HORIZONTAL).grid(row=12, column=0, columnspan=2, sticky=ew, pady=6)

        self.start_over_button = ttk.Button(SF, text=↺  Start Over,
                                            command=self.start_over, style='warning.TButton')
        self.start_over_button.grid(row=13, column=0, padx=6, pady=(0,4), sticky=ew)
        ttk.Button(SF, text=💾  Save Settings,
                   command=self.save_settings
                   ).grid(row=13, column=1, padx=6, pady=(0,4), sticky=ew)
    
    def create_results_widgets(self)
        Create widgets for results frame.

        filter_frame = ttk.Frame(self.results_frame)
        filter_frame.pack(fill=X, pady=(0, 8))

        ttk.Label(filter_frame, text=🔍  Filter, font=(Helvetica, 9)).pack(side=LEFT, padx=(0, 4))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add(write, self.filter_results)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, font=(Helvetica, 9), width=22)
        filter_entry.pack(side=LEFT, padx=(0, 12))

        ttk.Label(filter_frame, text=Min Score, font=(Helvetica, 9)).pack(side=LEFT, padx=(0, 4))
        self.min_score_var = tk.IntVar(value=0)
        score_spinbox = ttk.Spinbox(filter_frame, from_=0, to=100, width=5,
                                    textvariable=self.min_score_var, font=(Helvetica, 9))
        score_spinbox.pack(side=LEFT, padx=(0, 12))
        self.min_score_var.trace_add(write, self.filter_results)

        self.recheck_button = ttk.Button(filter_frame, text=↻  Re-check Working,
                                         command=self.recheck_working, state=DISABLED,
                                         style=info.TButton)
        self.recheck_button.pack(side=LEFT)

        columns = ('proxy', 'type', 'latency', 'speed', 'anonymity', 'country', 'reliability', 'score')
        style = ttk.Style()
        style.configure(Treeview, font=(Consolas, 10), rowheight=26)
        style.configure(Treeview.Heading, font=(Helvetica, 9, bold))
        self.tree = ttk.Treeview(self.results_frame, columns=columns, show='headings')
        self.tree.pack(side=LEFT, fill=BOTH, expand=YES)

        self.tree.tag_configure(elite,       background=#1a2e1a, foreground=#5cb85c)
        self.tree.tag_configure(anonymous,   background=#2e2a1a, foreground=#f0ad4e)
        self.tree.tag_configure(transparent, background=#2e1a1a, foreground=#d9534f)
        for col in columns
            self.tree.heading(col, text=col.capitalize().replace('_', ' '), 
                            command=lambda c=col self.sort_column(c, False))
            self.tree.column(col, width=100, anchor=CENTER)
        self.tree.column('proxy', width=280, anchor=W)
        self.tree.column('type', width=70)
        self.tree.column('latency', width=80)
        self.tree.column('speed', width=100)
        self.tree.column('reliability', width=80)
        self.tree.column('score', width=60)
        

        vsb = ttk.Scrollbar(self.results_frame, orient=vertical, command=self.tree.yview)
        vsb.pack(side=RIGHT, fill=Y)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.bind('TreeviewSelect', self.on_tree_select)
    
    def create_status_bar(self)
        Create status bar at bottom of window.
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=X, side=BOTTOM, pady=(5, 0))
        

        self.status_label = ttk.Label(status_frame, text=Ready to start...,
                                      font=(Helvetica, 9))
        self.status_label.pack(side=LEFT, padx=(8, 4))

        self.progress_bar = ttk.Progressbar(status_frame, orient=HORIZONTAL,
                                            mode='determinate', style=info.Horizontal.TProgressbar)
        self.progress_bar.pack(side=LEFT, fill=X, expand=YES, padx=(0, 8))

        self.copy_button = ttk.Button(status_frame, text=📋 Copy Selected,
                                      command=self.copy_selected, state=DISABLED)
        self.copy_button.pack(side=RIGHT, padx=(4, 8))

        self.copy_all_button = ttk.Button(status_frame, text=📋 Copy All Working,
                                          command=self.copy_all_working, state=DISABLED,
                                          style=success.TButton)
        self.copy_all_button.pack(side=RIGHT, padx=4)

        self.save_button = ttk.Button(status_frame, text=💾 Export Results,
                                      command=self.export_results, state=DISABLED,
                                      style=primary.TButton)
        self.save_button.pack(side=RIGHT, padx=4)
        

        self.status_frame = status_frame
    
    def update_status_bar_info(self)
        Update status bar with current information.
        if not self.is_checking
            current_time = datetime.now().strftime(%Y-%m-%d %H%M%S)
            self.status_label.config(text=fReady to start...  {current_time})

            try
                s = ttk.Style()
                s.configure(info.Horizontal.TProgressbar, troughcolor=#1e2a3a,
                             background=#4a90d9)
            except Exception
                pass
        else

            try
                s = ttk.Style()
                s.configure(info.Horizontal.TProgressbar, troughcolor=#1a2e1a,
                             background=#28a745)
            except Exception
                pass
        self.root.after(1000, self.update_status_bar_info)
    
    def show_user_guide(self)
        Show a rich User Guide window explaining every feature.
        win = tk.Toplevel(self.root)
        win.title(ProxVault — User Guide)
        win.geometry(680x720)
        win.configure(bg=#0d1117)
        win.resizable(True, True)

        hdr = tk.Frame(win, bg=#141c2e, height=52)
        hdr.pack(fill=X)
        hdr.pack_propagate(False)
        tk.Frame(hdr, bg=#4a90d9, width=4).pack(side=LEFT, fill=Y)
        tk.Label(hdr, text=  ProxVault — User Guide, bg=#141c2e,
                 fg=#ffffff, font=(Helvetica, 13, bold)).pack(side=LEFT, padx=8, pady=10)
        tk.Label(hdr, text=Everything you need to know, bg=#141c2e,
                 fg=#4a90d9, font=(Helvetica, 8)).pack(side=LEFT)

        container = tk.Frame(win, bg=#0d1117)
        container.pack(fill=BOTH, expand=YES)
        canvas = tk.Canvas(container, bg=#0d1117, highlightthickness=0)
        sb = ttk.Scrollbar(container, orient=VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side=RIGHT, fill=Y)
        canvas.pack(side=LEFT, fill=BOTH, expand=YES)
        inner = tk.Frame(canvas, bg=#0d1117)
        inner_id = canvas.create_window((0, 0), window=inner, anchor=nw)

        def _resize(e)
            canvas.itemconfig(inner_id, width=e.width)
        canvas.bind(Configure, _resize)
        inner.bind(Configure, lambda e canvas.configure(scrollregion=canvas.bbox(all)))

        def _on_scroll(e) canvas.yview_scroll(int(-1(e.delta120)), units)
        win.bind(MouseWheel, _on_scroll)
        win.protocol(WM_DELETE_WINDOW, lambda (win.unbind(MouseWheel), win.destroy()))

        def section(title, color=#4a90d9)
            tk.Frame(inner, bg=color, height=2).pack(fill=X, padx=16, pady=(18, 0))
            tk.Label(inner, text=title, bg=#0d1117, fg=color,
                     font=(Helvetica, 11, bold)).pack(anchor=W, padx=18, pady=(4, 2))

        def item(icon, title, desc)
            row = tk.Frame(inner, bg=#141c2e,
                           highlightbackground=#1e2a3a, highlightthickness=1)
            row.pack(fill=X, padx=16, pady=2)
            tk.Label(row, text=icon, bg=#141c2e, fg=#ffffff,
                     font=(Helvetica, 13), width=3).pack(side=LEFT, anchor=N, pady=8)
            col = tk.Frame(row, bg=#141c2e)
            col.pack(side=LEFT, fill=X, expand=YES, pady=6, padx=(0, 8))
            tk.Label(col, text=title, bg=#141c2e, fg=#e0e0e0,
                     font=(Helvetica, 9, bold), anchor=W).pack(fill=X)
            tk.Label(col, text=desc, bg=#141c2e, fg=#8b949e,
                     font=(Helvetica, 9), anchor=W, wraplength=530, justify=LEFT
                     ).pack(fill=X)

        section(STEP 1 — INPUT PROXIES, #4a90d9)
        item(📝, Paste Proxies,
             Paste proxies directly into the text box. One proxy per line.nAccepted formats  IPPORT  or  socks5IPPORT)
        item(📂, Import from File,
             Load a .txt or .csv file. Duplicates are removed automatically.)
        item(⬇, Scrape Proxies,
             Select a protocol and click Scrape to download a fresh public proxy list from GitHub. New proxies are merged with any you already have.)

        section(STEP 2 — SETTINGS, #20c997)
        item(🌐, Test URL,
             The website used to verify each proxy. Default is httpbin.org. For best results, change this to your actual target site (e.g. httpswww.google.com). A proxy that passes httpbin may still be blocked on your target.)
        item(⏱, Timeout,
             Seconds to wait before marking a proxy dead. Lower = faster scan but may miss slow proxies. Recommended 8-10s.)
        item(🔀, Threads,
             How many proxies are tested simultaneously. Higher = faster, but uses more CPU. Recommended 50-100. Max is 150.)
        item(⚡, Enable Speed Test,
             Measures download speed for each proxy. This is slow (adds up to 25s per proxy). Leave OFF for fast scanning. Turn ON only when speed data is needed.)
        item(🌍, Target Countries,
             Optional. Enter country names separated by commas. Proxies from these countries get a score bonus.)

        section(STEP 3 — RUNNING, #fd7e14)
        item(▶, Start Checking,
             Tests all proxies in the input box. Results appear in real time. Each proxy is tested against 4 URLs — must pass 2 or more to be marked Working.)
        item(■, Stop,     Stops checking. Results found so far are kept.)
        item(↺, Start Over, Clears all results and proxies so you can start fresh.)
        item(↻, Re-check Working,
             Re-tests your current working list. Useful because free proxies can die within minutes.)

        section(STAT CARDS, #6f42c1)
        item(🔵, TOTAL,   Total proxies in the current batch.)
        item(🟢, WORKING, Proxies confirmed working so far.)
        item(🔴, DEAD,    Proxies that failed all tests.)
        item(🟠, RATE,    Proxies checked per second.)
        item(🟣, ELAPSED, Time since checking started.)
        item(🔵, ETA,     Estimated time until all proxies are checked.)

        section(RESULTS TABLE, #28a745)
        item(🟢, Green rows,   Elite proxy — completely hides your real IP. Best quality.)
        item(🟡, Yellow rows,  Anonymous proxy — hides your IP but reveals it is a proxy.)
        item(🔴, Red rows,     Transparent proxy — your real IP leaks through. Avoid for privacy.)
        item(🔍, Filter box,   Search results by IP, country, anonymity level, etc.)
        item(📊, Min Score,
             Hides proxies below this quality score (0–100). With Speed Test OFF keep this at 0 (max score is ~55 without speed data). With Speed Test ON you can use 60–75.)
        item(📋, Copy All Working, Copies every working proxy to clipboard in one click.)
        item(💾, Export Results,   Save as CSV, JSON, TXT, HTML or PDF.)

        section(SCORE BREAKDOWN (0–100), #4a90d9)
        item(⚡, Latency   30%,    Proxy response time. Under 0.5s = excellent.)
        item(📶, Speed     30%, Download speed. Only counted with Speed Test ON.)
        item(🕵, Anonymity 15%, Elite=100, Anonymous=70, Transparent=30.)
        item(✅, Reliability 10%,  Ratio of test URLs passed (44 is perfect).)
        item(📈, Consistency 10%,Stable performance across multiple checks = higher score.)
        item(🌍, Geo Relevance 5%,Bonus if proxy matches your Target Countries.)

        section(PRO TIPS, #dc3545)
        item(💡, Best workflow,
             Scrape → Check (Speed Test OFF) → Filter to Elite + sort by Latency → Re-check → Copy All Working.)
        item(💡, Use your real target URL,
             Change Test URL to the site you actually need (Google, Amazon, etc.) for accurate results.)
        item(💡, Proxies die fast,
             Free proxies can go offline within minutes. Always Re-check before using them.)

        tk.Frame(inner, bg=#0d1117, height=20).pack()
        ttk.Button(win, text=  Close  , command=win.destroy,
                   style=primary.TButton).pack(pady=10)

    def show_about_dialog(self)
        Show about dialog.
        win = tk.Toplevel(self.root)
        win.title(About ProxVault)
        win.geometry(400x290)
        win.configure(bg=#0d1117)
        win.resizable(False, False)

        tk.Frame(win, bg=#4a90d9, height=3).pack(fill=X)
        c = tk.Canvas(win, width=64, height=64, bg=#0d1117, highlightthickness=0)
        c.pack(pady=(20, 6))
        c.create_oval(4, 4, 60, 60, fill=#141c2e, outline=#4a90d9, width=2)
        c.create_oval(16, 16, 48, 48, fill=#1a2a4a, outline=#2d6bbd, width=1)
        c.create_rectangle(24, 36, 40, 50, fill=#4a90d9, outline=)
        c.create_arc(24, 22, 40, 42, start=0, extent=180, style=arc, outline=#4a90d9, width=2)
        c.create_oval(30, 41, 34, 45, fill=#0d1117, outline=)

        tk.Label(win, text=APP_NAME, bg=#0d1117, fg=#ffffff,
                 font=(Helvetica, 18, bold)).pack()
        tk.Label(win, text=v{} — Proxy Intelligence Platform.format(APP_VERSION),
                 bg=#0d1117, fg=#4a90d9, font=(Helvetica, 9)).pack(pady=(2,0))
        tk.Frame(win, bg=#1a2a3a, height=1).pack(fill=X, pady=10, padx=30)
        tk.Label(win, text=Developed by  {}.format(AUTHOR_NAME),
                 bg=#0d1117, fg=#e0e0e0, font=(Helvetica, 10, bold)).pack()
        tk.Label(win, text=© {}  All rights reserved..format(datetime.now().year),
                 bg=#0d1117, fg=#6c757d, font=(Helvetica, 8)).pack(pady=(3,0))
        tk.Frame(win, bg=#1a2a3a, height=1).pack(fill=X, pady=10, padx=30)
        btn_row = tk.Frame(win, bg=#0d1117)
        btn_row.pack()
        ttk.Button(btn_row, text=  User Guide  ,
                   command=lambda (win.destroy(), self.show_user_guide()),
                   style=info.TButton).pack(side=LEFT, padx=6)
        ttk.Button(btn_row, text=  Close  ,
                   command=win.destroy, style=secondary.TButton).pack(side=LEFT, padx=6)

    def clear_cache(self)
        Clear proxy cache.
        proxy_cache.clear()
        messagebox.showinfo(Cache Cleared, Proxy cache has been cleared.)
        logger.info(Proxy cache cleared by user)
    
    def view_cache_stats(self)
        Display statistics about proxy cache.
        cache_size = len(proxy_cache.cache)
        if cache_size == 0
            messagebox.showinfo(Cache Stats, Cache is empty.)
            return
        
        working_count = sum(1 for item in proxy_cache.cache.values() 
                          if item['result'].get('status') == 'working')
        failed_count = cache_size - working_count
        

        working_results = [item['result'] for item in proxy_cache.cache.values() 
                         if item['result'].get('status') == 'working']
        avg_score = 0
        if working_results
            avg_score = sum(r.get('score', 0) for r in working_results)  len(working_results)
        
        stats_text = (
            fCache Statisticsnn
            fTotal cached proxies {cache_size}n
            fWorking proxies {working_count}n
            fFailed proxies {failed_count}n
            fAverage quality score {avg_score.1f}100n
            fCache expiry {proxy_cache.expiry.total_seconds()  3600.1f} hours
        )
        
        messagebox.showinfo(Cache Statistics, stats_text)
    
    def save_settings(self)
        Save current settings to configuration file.
        try
            config_manager.set('General', 'test_url', self.test_url_entry.get())
            config_manager.set('General', 'timeout', self.timeout_spinbox.get())
            config_manager.set('General', 'max_threads', self.threads_spinbox.get())
            

            config_manager.set('ProxyScraping', 'base_url', self.scrape_base_url_entry.get())
            

            target_countries_str = self.target_countries_entry.get().strip()
            if target_countries_str
                self.target_countries = [c.strip() for c in target_countries_str.split(',')]
                config_manager.set('Filtering', 'target_countries', target_countries_str)
            
            messagebox.showinfo(Settings Saved, Your settings have been saved successfully.)
            logger.info(Settings saved by user)
        except Exception as e
            messagebox.showerror(Save Error, fFailed to save settings {e})
            logger.error(fFailed to save settings {e})
    
    def start_scraping(self)
        Start scraping proxies from selected source.
        if hasattr(self, '_scraping') and self._scraping
            messagebox.showinfo(Scraping, Already scraping — please wait.)
            return
        self._scraping = True

        protocol = self.scrape_protocol_var.get()
        if not protocol
            self._scraping = False
            messagebox.showwarning(No Protocol, Please select a proxy protocol to scrape.)
            return

        self.scrape_button.config(state=DISABLED)
        self.protocol_combobox.config(state=DISABLED)
        self.status_label.config(text=fScraping {protocol.upper()} proxies...)
        logger.info(fStarted scraping {protocol.upper()} proxies)
        threading.Thread(target=self.run_scraper_thread, args=(protocol,), daemon=True).start()
    
    def run_scraper_thread(self, protocol)
        Scrape proxies from GitHub repository.

        base_url = config_manager.get('ProxyScraping', 'base_url')

        base_url = base_url.rstrip('')
        scrape_url = f{base_url}{protocol}.txt
        error_message = None
        headers = header_manager.get_headers()
        
        try
            logger.info(fScraping proxies from {scrape_url})
            response = requests.get(scrape_url, timeout=15, headers=headers)
            response.raise_for_status()
            

            if not response.text
                error_message = fEmpty response from {scrape_url}
                logger.error(error_message)
                scraped_proxies = None
            else
                scraped_proxies = response.text.strip().split('n')

                scraped_proxies = [p.strip() for p in scraped_proxies if p.strip()]
                logger.info(fSuccessfully scraped {len(scraped_proxies)} proxies)
                
        except requests.exceptions.RequestException as e
            error_message = fFailed to scrape from {scrape_url}n{e.__class__.__name__} {str(e)}
            logger.error(fScraping error {error_message})
            scraped_proxies = None
        except Exception as e
            error_message = fUnexpected error scraping from {scrape_url}n{e.__class__.__name__} {str(e)}
            logger.error(fScraping error {error_message})
            scraped_proxies = None
        
        if scraped_proxies
            if protocol in ['socks4', 'socks5']

                scraped_proxies = [
                    p if p.startswith(f{protocol}) else f{protocol}{p}
                    for p in scraped_proxies
                ]
            elif protocol == 'https'
                scraped_proxies = [
                    p if p.startswith('https') else fhttps{p}
                    for p in scraped_proxies
                ]
            elif protocol == 'http'

                scraped_proxies = [
                    p[len('http')] if p.startswith('http') else p
                    for p in scraped_proxies
                ]
            self.root.after(0, self.update_proxies_from_scraper, scraped_proxies, protocol)
        else
            self.root.after(0, lambda msg=error_message messagebox.showerror(Scraping Error, msg))
        
        self.root.after(0, lambda self.scrape_button.config(state=NORMAL))
        self.root.after(0, lambda self.protocol_combobox.config(state=readonly))
        self.root.after(0, lambda self.status_label.config(text=Scraping complete. if scraped_proxies else Scraping failed.))
        self._scraping = False
    
    def update_proxies_from_scraper(self, new_proxies, protocol)
        Update the proxy list with newly scraped proxies.
        valid_new_proxies = [p.strip() for p in new_proxies if validate_proxy(p)]
        current_text = self.proxy_text.get(1.0, END).strip()
        current_proxies_set = set(current_text.split('n')) if current_text else set()
        new_proxies_set = set(valid_new_proxies)
        added_count = len(new_proxies_set - current_proxies_set)
        final_proxies = sorted(list(current_proxies_set.union(new_proxies_set)))
        
        self.proxy_text.delete(1.0, END)
        self.proxy_text.insert(1.0, n.join(final_proxies))
        messagebox.showinfo(Success, 
                          fScraped {len(new_proxies_set)} {protocol.upper()} proxies.n
                          fAdded {added_count} new unique proxies to the list.)
        logger.info(fUpdated proxy list added {added_count} new {protocol.upper()} proxies)
    
    def filter_results(self, args)
        Filter and display proxy results based on search criteria.
        search_term = self.filter_var.get().lower()
        try
            min_score = self.min_score_var.get()
        except Exception
            min_score = 0
        
        self.tree.delete(self.tree.get_children())
        
        for p_info in self.working_proxies

            matches_search = any(search_term in str(val).lower() for val in p_info.values())
            

            meets_score = p_info.get('score', 0) = min_score
            
            if matches_search and meets_score
                self.tree.insert('', END, tags=(_anonymity_tag(p_info.get('anonymity','Elite')),),
                                 values=(
                    p_info['proxy'], 
                    p_info['type'], 
                    f{p_info['latency']}s, 
                    p_info['speed'], 
                    p_info['anonymity'], 
                    p_info['country'],
                    p_info.get('reliability', 'NA'),
                    f{p_info.get('score', 0)}100
                ))
    
    def recheck_working(self)
        Re-check all working proxies.
        proxies_to_recheck = [p['proxy'] for p in self.working_proxies]
        if not proxies_to_recheck
            messagebox.showinfo(Info, No working proxies to re-check.)
            return
        
        logger.info(fRe-checking {len(proxies_to_recheck)} working proxies)
        self.proxy_text.delete('1.0', END)
        self.proxy_text.insert('1.0', n.join(proxies_to_recheck))
        self.start_checking()
    
    def export_results(self)
        Export working proxies to a file.
        if not self.working_proxies
            messagebox.showwarning(No Results, There are no working proxies to export.)
            return
        
        filepath = filedialog.asksaveasfilename(
            title=Export Working Proxies,
            filetypes=(
                (Text File, .txt),
                (CSV File, .csv),
                (JSON File, .json)
            )
        )
        
        if not filepath
            return
        

        def _sort_key(p)
            try
                return (-p.get('score', 0), float(p['latency']))
            except (ValueError, TypeError)
                return (-p.get('score', 0), 9999.0)
        sorted_proxies = sorted(self.working_proxies, key=_sort_key)
        
        try
            if filepath.endswith('.txt')
                with open(filepath, w) as f
                    for p_info in sorted_proxies
                        f.write(p_info['proxy'] + 'n')
            elif filepath.endswith('.csv')
                with open(filepath, w, newline=, encoding=utf-8) as f
                    writer = csv.DictWriter(f, fieldnames=sorted_proxies[0].keys())
                    writer.writeheader()
                    writer.writerows(sorted_proxies)
            elif filepath.endswith('.json')
                with open(filepath, w, encoding=utf-8) as f
                    json.dump(sorted_proxies, f, indent=4)
            
            logger.info(fExported {len(sorted_proxies)} working proxies to {filepath})
            messagebox.showinfo(Success, 
                              f{len(sorted_proxies)} working proxies exported ton{filepath})
        except Exception as e
            logger.error(fExport error {e})
            messagebox.showerror(Export Error, fAn error occurred {e})
    
    def import_from_file(self)
        Import proxies from a file.
        filepath = filedialog.askopenfilename(
            title=Import Proxies from File,
            filetypes=((Proxy Files, .txt .csv .json), (Text Files, .txt),
                       (CSV Files, .csv), (All Files, .))
        )
        
        if not filepath
            return
        
        try
            with open(filepath, 'r') as f
                proxies = f.read()
                self.proxy_text.delete('1.0', END)
                self.proxy_text.insert('1.0', proxies)
            
            logger.info(fImported proxies from {filepath})
        except Exception as e
            logger.error(fImport error {e})
            messagebox.showerror(Import Error, fFailed to read file {e})
    
    def sort_column(self, col, reverse)
        Sort the results table by the specified column.
        try
            data = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]
            
            if col in ['latency', 'speed']
                data.sort(key=lambda t float(t[0].split(' ')[0]) if t[0] not in ('NA','') else -1, reverse=reverse)
            elif col == 'score'
                data.sort(key=lambda t float(t[0].split('')[0]) if t[0] not in ('NA','') else -1, reverse=reverse)
            elif col == 'reliability'
                def _sort_reliability(text)
                    try
                        parts = text.split('')
                        return int(parts[0])  int(parts[1]) if len(parts) == 2 else 0
                    except (ValueError, IndexError, ZeroDivisionError)
                        return 0
                data.sort(key=lambda t _sort_reliability(t[0]), reverse=reverse)
            else
                data.sort(key=lambda t t[0].lower(), reverse=reverse)
            
            for index, (val, item) in enumerate(data)
                self.tree.move(item, '', index)
            
            self.tree.heading(col, command=lambda self.sort_column(col, not reverse))
        except Exception as e
            logger.error(fError sorting column {col} {e})
            print(fError sorting column {col} {e})
    
    def update_status_label(self)
        Update the status label with current progress information.
        self._update_stat_cards()
        if self.progress_tracker
            progress = self.progress_tracker.get_progress()
            status_text = (
                fChecked {progress['checked']}{progress['total']}  
                fWorking {progress['working']}  
                fFailed {progress['failed']}  
                fProgress {progress['progress'].1f}%  
                fRate {progress['rate'].1f} proxiessec  
                fETA {progress['remaining'].0f}s
            )
            self.status_label.config(text=status_text)
        else
            status_text = fChecked {self.working_count}{self.progress_bar['maximum']}  
            status_text += fWorking {self.working_count}  Failed {self.failed_count}
            self.status_label.config(text=status_text)
    
    def start_checking(self)
        Start checking proxies.
        proxies = self.proxy_text.get('1.0', tk.END).strip().split('n')
        proxies = [p.strip() for p in proxies if p.strip()]
        

        seen = set()
        unique_proxies = []
        for p in proxies
            if p not in seen
                seen.add(p)
                unique_proxies.append(p)
        duplicates_removed = len(proxies) - len(unique_proxies)
        proxies = unique_proxies
        if duplicates_removed
            logger.info(fRemoved {duplicates_removed} duplicate proxies before checking)
        
        if not proxies
            messagebox.showwarning(Input Empty, Please paste or import at least one proxy.)
            return
        

        self.progress_tracker = ProgressTracker(len(proxies))
        

        self.start_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.save_button.config(state=DISABLED)
        self.recheck_button.config(state=DISABLED)
        self.copy_button.config(state=DISABLED)
        

        self.tree.delete(self.tree.get_children())
        self.working_proxies.clear()
        self.stop_event.clear()
        self.working_count = 0
        self.failed_count = 0
        

        self.progress_bar[maximum] = len(proxies)
        self.progress_bar[value] = 0
        self.update_status_label()
        

        self.q = queue.Queue()
        

        self.executor = None
        

        self.is_checking = True
        

        timeout     = int(self.timeout_spinbox.get())
        max_workers = int(self.threads_spinbox.get())
        test_url    = self.test_url_entry.get().strip() or config_manager.get('General', 'test_url')
        test_speed  = self.speed_test_var.get()

        logger.info(fStarting to check {len(proxies)} proxies)
        self.checker_thread = threading.Thread(
            target=self.run_checker_thread,
            args=(proxies, timeout, max_workers, test_url, test_speed),
            daemon=True
        )
        self.checker_thread.start()
        self._start_spinner()

        self.root.after(100, self.process_queue)
    
    def stop_checking(self)
        Stop proxy checking process.
        if self.checker_thread and self.checker_thread.is_alive()
            self.status_label.config(text=Stopping...)
            self.stop_event.set()
            self.stop_button.config(state=DISABLED)

            if hasattr(self, 'executor') and self.executor and not self.executor._shutdown
                self.executor.shutdown(wait=False) if __import__('sys').version_info  (3,9) else self.executor.shutdown(wait=False, cancel_futures=True)
            logger.info(Proxy checking stopped by user)
    
    def start_over(self)
        Reset the application to its initial state.

        if self.is_checking
            self.stop_checking()

            if self.checker_thread and self.checker_thread.is_alive()
                self.checker_thread.join(timeout=2)
        

        self.proxy_text.delete('1.0', END)
        self.tree.delete(self.tree.get_children())
        self.working_proxies.clear()
        self.working_count = 0
        self.failed_count = 0
        self.progress_bar[value] = 0
        

        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)
        self.save_button.config(state=DISABLED)
        self.recheck_button.config(state=DISABLED)
        self.copy_button.config(state=DISABLED)
        self.copy_all_button.config(state=DISABLED)
        

        self.is_checking = False
        self.progress_tracker = None
        self._update_stat_cards()
        self._stop_spinner()
        

        self.status_label.config(text=Ready to start...)
        
        logger.info(Application reset to initial state)
    
    def run_checker_thread(self, proxies, timeout, max_workers, test_url, test_speed)
        Run the proxy checking in a separate thread.
        All tkinter widget values are read on the main thread and passed in as args
        to avoid unsafe cross-thread widget access.
        real_ip = get_real_ip()
        
        logger.info(fChecking {len(proxies)} proxies  threads={max_workers} timeout={timeout}s speed_test={test_speed})

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        try
            future_to_proxy = {
                self.executor.submit(
                    check_proxy, 
                    proxy, 
                    real_ip, 
                    timeout, 
                    self.q, 
                    self.stop_event, 
                    test_url,
                    test_speed
                ) proxy 
                for proxy in proxies
            }
            
            for future in concurrent.futures.as_completed(future_to_proxy)
                if self.stop_event.is_set()

                    self.executor.shutdown(wait=False) if __import__('sys').version_info  (3,9) else self.executor.shutdown(wait=False, cancel_futures=True)
                    break
        except Exception as e
            logger.error(fError in checker thread {e})
        finally

            if self.executor and not self.executor._shutdown
                self.executor.shutdown(wait=False)
        
        logger.info(fFinished checking proxies. Found {self.working_count} working proxies)
        self.q.put(None)
    
    def process_queue(self)
        Process results from the proxy checking queue.
        try
            result = self.q.get_nowait()
            
            if result is None

                if self.stop_event.is_set()
                    self.status_label.config(
                        text=fProcess stopped. Found {self.working_count} working proxies.
                    )
                    logger.info(fProxy checking stopped. Found {self.working_count} working proxies)
                else
                    self.progress_bar[value] = self.progress_bar[maximum]
                    self.status_label.config(
                        text=fFinished! Found {self.working_count} working proxies.
                    )
                    logger.info(fProxy checking completed. Found {self.working_count} working proxies)
                

                self.start_button.config(state=NORMAL)
                self.stop_button.config(state=DISABLED)
                
                if self.working_proxies
                    self.save_button.config(state=NORMAL)
                    self.recheck_button.config(state=NORMAL)
                    self.copy_all_button.config(state=NORMAL)
                

                self._stop_spinner()

                self.root.after(3000, self.reset_checking_state)
                return
            

            if result['status'] == 'working'
                self.working_count += 1
                self.working_proxies.append(result)

                try
                    min_score = self.min_score_var.get()
                except Exception
                    min_score = 0
                search_term = self.filter_var.get().lower()
                meets_filter = (
                    result.get('score', 0) = min_score and
                    (not search_term or any(search_term in str(v).lower() for v in result.values()))
                )
                if meets_filter
                    self.tree.insert('', END, tags=(_anonymity_tag(result.get('anonymity','Elite')),),
                                     values=(
                        result['proxy'],
                        result['type'],
                        f{result['latency']}s,
                        result['speed'],
                        result['anonymity'],
                        result['country'],
                        result.get('reliability', 'NA'),
                        f{result.get('score', 0)}100
                    ))
                logger.debug(fWorking proxy found {result['proxy']})
            else
                self.failed_count += 1

            self.progress_bar[value] += 1
            

            if self.progress_tracker
                self.progress_tracker.update(result['status'])
            

            if not self.stop_event.is_set()
                self.update_status_label()
            

            try
                if self.root.winfo_exists()
                    self.root.after(10, self.process_queue)
            except Exception
                pass
        except queue.Empty

            if self.checker_thread and self.checker_thread.is_alive()
                try
                    if self.root.winfo_exists()
                        self.root.after(100, self.process_queue)
                except Exception
                    pass
    
    def reset_checking_state(self)
        Reset the checking state after checking is complete.
        self.is_checking = False

        self.status_label.config(text=Ready to start...)
    
    def on_tree_select(self, event)
        Handle treeview selection events.
        self.copy_button.config(state=NORMAL if self.tree.selection() else DISABLED)
    
    def copy_selected(self)
        Copy selected proxies to clipboard.
        selected_items = self.tree.selection()
        
        if not selected_items
            return
        

        proxies_to_copy = [self.tree.item(item_id, values)[0] for item_id in selected_items]
        

        self.root.clipboard_clear()
        self.root.clipboard_append(n.join(proxies_to_copy))
        

        self.status_label.config(text=fCopied {len(proxies_to_copy)} proxies to clipboard.)
        logger.info(fCopied {len(proxies_to_copy)} proxies to clipboard)
    
    def copy_all_working(self)
        Copy all working proxies to clipboard.
        if not self.working_proxies
            messagebox.showinfo(Nothing to Copy, No working proxies found yet.)
            return
        all_proxies = [p['proxy'] for p in self.working_proxies]
        self.root.clipboard_clear()
        self.root.clipboard_append(n.join(all_proxies))
        self.status_label.config(text=fCopied all {len(all_proxies)} working proxies to clipboard.)
        logger.info(fCopied all {len(all_proxies)} working proxies to clipboard)
    
    def show_analytics(self)
        Show analytics dashboard with proxy performance metrics.
        if not self.working_proxies
            messagebox.showinfo(No Data, No proxy data available for analytics.)
            return

        if hasattr(self, '_analytics_win') and self._analytics_win and self._analytics_win.winfo_exists()
            self._analytics_win.lift()
            return

        analytics_window = tk.Toplevel(self.root)
        self._analytics_win = analytics_window
        analytics_window.title(Proxy Analytics)
        analytics_window.geometry(800x600)
        

        notebook = ttk.Notebook(analytics_window)
        notebook.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        

        performance_tab = ttk.Frame(notebook)
        notebook.add(performance_tab, text=Performance)
        

        from matplotlib.figure import Figure
        fig = Figure(figsize=(8, 6), dpi=100)
        ax1 = fig.add_subplot(211)
        ax2 = fig.add_subplot(212)
        

        latencies = []
        for p in self.working_proxies
            try
                latencies.append(float(p['latency']))
            except (ValueError, TypeError)
                latencies.append(0.0)
        speeds = []
        for p in self.working_proxies
            try
                speeds.append(float(p['speed'].split(' ')[0]))
            except (ValueError, AttributeError)
                speeds.append(0)
        
        scores = [p.get('score', 0) for p in self.working_proxies]
        

        ax1.hist(latencies, bins=20, color='skyblue', edgecolor='black')
        ax1.set_title('Proxy Latency Distribution')
        ax1.set_xlabel('Latency (seconds)')
        ax1.set_ylabel('Count')
        

        ax2.hist(speeds, bins=20, color='lightgreen', edgecolor='black')
        ax2.set_title('Proxy Speed Distribution')
        ax2.set_xlabel('Speed (Mbps)')
        ax2.set_ylabel('Count')
        
        fig.tight_layout()
        

        canvas = FigureCanvasTkAgg(fig, master=performance_tab)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=BOTH, expand=YES)
        

        stats_tab = ttk.Frame(notebook)
        notebook.add(stats_tab, text=Statistics)
        

        stats_frame = ttk.Frame(stats_tab)
        stats_frame.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        

        avg_latency = sum(latencies)  len(latencies) if latencies else 0
        avg_speed = sum(speeds)  len(speeds) if speeds else 0
        avg_score = sum(scores)  len(scores) if scores else 0
        
        min_latency = min(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0
        
        min_speed = min(speeds) if speeds else 0
        max_speed = max(speeds) if speeds else 0
        
        min_score = min(scores) if scores else 0
        max_score = max(scores) if scores else 0
        

        stats_data = [
            (Metric, Value),
            (Total Proxies, len(self.working_proxies)),
            (Average Latency, f{avg_latency.2f}s),
            (Minimum Latency, f{min_latency.2f}s),
            (Maximum Latency, f{max_latency.2f}s),
            (Average Speed, f{avg_speed.2f} Mbps),
            (Minimum Speed, f{min_speed.2f} Mbps),
            (Maximum Speed, f{max_speed.2f} Mbps),
            (Average Score, f{avg_score.2f}100),
            (Minimum Score, f{min_score.2f}100),
            (Maximum Score, f{max_score.2f}100)
        ]
        
        stats_tree = ttk.Treeview(stats_frame, columns=(Metric, Value), show='headings')
        stats_tree.heading(Metric, text=Metric)
        stats_tree.heading(Value, text=Value)
        
        for item in stats_data
            stats_tree.insert('', END, values=item)
        
        stats_tree.pack(fill=BOTH, expand=YES)
        

        country_tab = ttk.Frame(notebook)
        notebook.add(country_tab, text=Countries)
        

        from matplotlib.figure import Figure as MFigure
        fig2 = MFigure(figsize=(8, 6), dpi=100)
        ax3 = fig2.add_subplot(111)

        country_counts = {}
        for p in self.working_proxies
            country = p.get('country', 'Unknown')
            country_counts[country] = country_counts.get(country, 0) + 1

        sorted_countries = sorted(country_counts.items(), key=lambda x x[1], reverse=True)
        countries = [item[0] for item in sorted_countries[10]]
        counts    = [item[1] for item in sorted_countries[10]]

        ax3.bar(countries, counts, color='#4a90d9')
        ax3.set_title('Proxy Distribution by Country (Top 10)')
        ax3.set_xlabel('Country')
        ax3.set_ylabel('Count')
        ax3.tick_params(axis='x', rotation=45)
        fig2.tight_layout()

        canvas2 = FigureCanvasTkAgg(fig2, master=country_tab)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill=BOTH, expand=YES)

        analytics_window.protocol(WM_DELETE_WINDOW,
            lambda (fig.clf(), fig2.clf(), analytics_window.destroy()))

        logger.info(Analytics dashboard opened)
    
    def generate_report(self)
        Generate a detailed report of proxy checking results.
        if not self.working_proxies
            messagebox.showwarning(No Results, There are no working proxies to generate a report for.)
            return
        

        report_format = messagebox.askyesno(Report Format, Generate HTML reportnnYes HTMLnNo PDF)
        

        def _sort_key(p)
            try
                return (-p.get('score', 0), float(p['latency']))
            except (ValueError, TypeError)
                return (-p.get('score', 0), 9999.0)
        sorted_proxies = sorted(self.working_proxies, key=_sort_key)
        

        latencies = []
        for p in sorted_proxies
            try
                latencies.append(float(p['latency']))
            except (ValueError, TypeError)
                latencies.append(0.0)
        speeds = []
        for p in sorted_proxies
            try
                speeds.append(float(p['speed'].split(' ')[0]))
            except (ValueError, AttributeError)
                speeds.append(0)
        
        scores = [p.get('score', 0) for p in sorted_proxies]
        
        avg_latency = sum(latencies)  len(latencies) if latencies else 0
        avg_speed = sum(speeds)  len(speeds) if speeds else 0
        avg_score = sum(scores)  len(scores) if scores else 0
        

        if report_format
            html_content = f
            !DOCTYPE html
            html
            head
                titleProxy Checker Reporttitle
                style
                    body {{ font-family Arial, sans-serif; margin 20px; }}
                    h1 {{ color #333; }}
                    h2 {{ color #555; }}
                    table {{ border-collapse collapse; width 100%; margin-top 20px; }}
                    th, td {{ border 1px solid #ddd; padding 8px; text-align left; }}
                    th {{ background-color #f2f2f2; }}
                    trnth-child(even) {{ background-color #f9f9f9; }}
                    .summary {{ background-color #f0f7fe; padding 15px; border-radius 5px; margin-bottom 20px; }}
                style
            head
            body
                h1Proxy Checker Reporth1
                pGenerated on {datetime.now().strftime(%Y-%m-%d %H%M%S)}p
                
                div class=summary
                    h2Summaryh2
                    pTotal Proxies {len(sorted_proxies)}p
                    pAverage Latency {avg_latency.2f}sp
                    pAverage Speed {avg_speed.2f} Mbpsp
                    pAverage Score {avg_score.2f}100p
                div
                
                h2Proxy Detailsh2
                table
                    tr
                        thProxyth
                        thTypeth
                        thLatencyth
                        thSpeedth
                        thAnonymityth
                        thCountryth
                        thReliabilityth
                        thScoreth
                    tr
            
            
            for p in sorted_proxies
                html_content += f
                    tr
                        td{p['proxy']}td
                        td{p['type']}td
                        td{p['latency']}std
                        td{p['speed']}td
                        td{p['anonymity']}td
                        td{p['country']}td
                        td{p.get('reliability', 'NA')}td
                        td{p.get('score', 0)}100td
                    tr
                
            
            html_content += 
                table
            body
            html
            
            

            filepath = filedialog.asksaveasfilename(
                title=Save HTML Report,
                defaultextension=.html,
                filetypes=((HTML Files, .html),)
            )
            
            if filepath
                with open(filepath, 'w') as f
                    f.write(html_content)
                
                logger.info(fHTML report saved to {filepath})
                messagebox.showinfo(Report Generated, fHTML report saved ton{filepath})
        
        else
            try
                from reportlab.lib.pagesizes import letter
                from reportlab.lib import colors
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
                from reportlab.lib.styles import getSampleStyleSheet
                

                filepath = filedialog.asksaveasfilename(
                    title=Save PDF Report,
                    defaultextension=.pdf,
                    filetypes=((PDF Files, .pdf),)
                )
                
                if not filepath
                    return
                

                doc = SimpleDocTemplate(filepath, pagesize=letter)
                elements = []
                styles = getSampleStyleSheet()
                

                title = Paragraph(Proxy Checker Report, styles['Title'])
                elements.append(title)
                elements.append(Spacer(1, 12))
                

                date = Paragraph(fGenerated on {datetime.now().strftime('%Y-%m-%d %H%M%S')}, styles['Normal'])
                elements.append(date)
                elements.append(Spacer(1, 12))
                

                summary_title = Paragraph(Summary, styles['Heading2'])
                elements.append(summary_title)
                
                summary_data = [
                    [Total Proxies, str(len(sorted_proxies))],
                    [Average Latency, f{avg_latency.2f}s],
                    [Average Speed, f{avg_speed.2f} Mbps],
                    [Average Score, f{avg_score.2f}100]
                ]
                
                summary_table = Table(summary_data, colWidths=[150, 200])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (1, 0), colors.lightblue),
                    ('TEXTCOLOR', (0, 0), (1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                elements.append(summary_table)
                elements.append(Spacer(1, 12))
                

                details_title = Paragraph(Proxy Details, styles['Heading2'])
                elements.append(details_title)
                

                table_data = [
                    [Proxy, Type, Latency, Speed, Anonymity, Country, Reliability, Score]
                ]
                
                for p in sorted_proxies
                    table_data.append([
                        p['proxy'],
                        p['type'],
                        f{p['latency']}s,
                        p['speed'],
                        p['anonymity'],
                        p['country'],
                        p.get('reliability', 'NA'),
                        f{p.get('score', 0)}100
                    ])
                

                table = Table(table_data, colWidths=[100, 50, 50, 50, 50, 50, 50, 50])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                elements.append(table)
                

                doc.build(elements)
                
                logger.info(fPDF report saved to {filepath})
                messagebox.showinfo(Report Generated, fPDF report saved ton{filepath})
            
            except ImportError
                messagebox.showerror(Missing Library, 
                                   ReportLab library is required for PDF reports.n
                                   Install it with pip install reportlab)
                logger.error(ReportLab library not found for PDF generation)
            except Exception as e
                logger.error(fError generating PDF report {e})
                messagebox.showerror(Report Error, fFailed to generate PDF report {e})
    
    def cleanup_on_exit(self)
        Clean up resources when the application exits.
        logger.info(Application shutting down)

        self.stop_event.set()

        if self.executor
            try
                self.executor.shutdown(wait=False) if __import__('sys').version_info  (3,9) else self.executor.shutdown(wait=False, cancel_futures=True)
            except Exception
                pass

        try
            config_manager.set('GUI', 'window_size', self.root.geometry())
            config_manager.save_config()
        except Exception
            pass

def get_real_ip()
    Get the real IP address of the current machine.
    try
        response = requests.get('httpsapi.ipify.orgformat=json', timeout=5)
        return response.json()['ip']
    except Exception
        logger.warning(Failed to get real IP address)
        return None

if __name__ == __main__
    try
        import socks
        logger.info(PySocks available — SOCKS4SOCKS5 proxies supported)
    except ImportError
        logger.warning(PySocks not installed — SOCKS4SOCKS5 proxies will ALL fail)
        def _warn_pysocks()
            import tkinter.messagebox as mb
            mb.showwarning(
                SOCKS Support Missing,
                PySocks is not installed.nn
                SOCKS4 and SOCKS5 proxies will fail to check.nn
                Fix this by runningn
                    pip install pysocksnn
                HTTP and HTTPS proxies are not affected.
            )
        root.after(500, _warn_pysocks)
    
    root = bs.Window(themename=darkly)
    app = ProxyCheckerApp(root)
    

    root.protocol(WM_DELETE_WINDOW, lambda (app.cleanup_on_exit(), root.destroy()))
    
    logger.info(Application started)
    root.mainloop()