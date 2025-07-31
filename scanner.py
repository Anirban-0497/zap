import os
import time
import logging
import requests
from zapv2 import ZAPv2
from urllib.parse import urlparse
from zap_manager import ZAPManager

logger = logging.getLogger(__name__)

class ZAPScanner:
    """OWASP ZAP scanner wrapper with enhanced functionality"""
    
    def __init__(self):
        self.zap_manager = ZAPManager()
        self.zap = None
        self.target_url = None
        self.scan_running = False
        
    def start_zap(self):
        """Start ZAP daemon and initialize API client"""
        try:
            logger.info("Starting ZAP daemon...")
            self.zap_manager.start_zap()
            
            # Wait for ZAP to be ready
            max_retries = 30
            for i in range(max_retries):
                try:
                    self.zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
                    # Test connection
                    self.zap.core.version
                    logger.info("ZAP is ready!")
                    break
                except Exception as e:
                    if i == max_retries - 1:
                        raise Exception(f"Failed to connect to ZAP after {max_retries} attempts: {str(e)}")
                    time.sleep(2)
            
            # Configure ZAP settings for better scanning
            self.configure_zap()
            
        except Exception as e:
            logger.error(f"Failed to start ZAP: {str(e)}")
            raise
    
    def configure_zap(self):
        """Configure ZAP for optimal scanning"""
        try:
            # Set spider options
            self.zap.spider.set_option_max_depth(5)
            self.zap.spider.set_option_max_children(10)
            self.zap.spider.set_option_thread_count(5)
            
            # Set active scan options
            self.zap.ascan.set_option_thread_per_host(5)
            self.zap.ascan.set_option_host_per_scan(1)
            
            logger.info("ZAP configuration completed")
            
        except Exception as e:
            logger.warning(f"Could not configure ZAP settings: {str(e)}")
    
    def spider_scan(self, target_url, update_callback=None):
        """Perform spider scan to discover all pages and links"""
        try:
            self.target_url = target_url
            self.scan_running = True
            
            logger.info(f"Starting spider scan for {target_url}")
            
            # Start spider scan
            scan_id = self.zap.spider.scan(target_url)
            
            # Monitor spider progress
            while int(self.zap.spider.status(scan_id)) < 100:
                if not self.scan_running:
                    self.zap.spider.stop(scan_id)
                    break
                
                progress = int(self.zap.spider.status(scan_id))
                if update_callback:
                    update_callback(10 + (progress * 0.4), f"Crawling website... {progress}%")
                
                time.sleep(2)
            
            # Get spider results
            spider_results = self.zap.spider.results(scan_id)
            urls_found = len(spider_results)
            
            logger.info(f"Spider scan completed. Found {urls_found} URLs")
            
            return {
                'scan_id': scan_id,
                'urls_found': urls_found,
                'urls': spider_results
            }
            
        except Exception as e:
            logger.error(f"Spider scan failed: {str(e)}")
            raise
    
    def active_scan(self, target_url, update_callback=None):
        """Perform active vulnerability scan"""
        try:
            logger.info(f"Starting active scan for {target_url}")
            
            # Start active scan
            scan_id = self.zap.ascan.scan(target_url)
            
            # Monitor active scan progress
            while int(self.zap.ascan.status(scan_id)) < 100:
                if not self.scan_running:
                    self.zap.ascan.stop(scan_id)
                    break
                
                progress = int(self.zap.ascan.status(scan_id))
                if update_callback:
                    update_callback(50 + (progress * 0.4), f"Security scanning... {progress}%")
                
                time.sleep(3)
            
            logger.info("Active scan completed")
            
            return {
                'scan_id': scan_id,
                'status': 'completed'
            }
            
        except Exception as e:
            logger.error(f"Active scan failed: {str(e)}")
            raise
    
    def get_scan_results(self):
        """Get comprehensive scan results including alerts and summary"""
        try:
            # Get all alerts
            alerts = self.zap.core.alerts()
            
            # Get summary information
            summary = self.zap.core.urls()
            
            # Categorize alerts by risk level
            risk_summary = {
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Informational': 0
            }
            
            for alert in alerts:
                risk = alert.get('risk', 'Informational')
                if risk in risk_summary:
                    risk_summary[risk] += 1
            
            # Get additional details
            sites = self.zap.core.sites()
            
            results = {
                'target_url': self.target_url,
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'alerts': alerts,
                'alert_count': len(alerts),
                'risk_summary': risk_summary,
                'urls_scanned': len(summary),
                'sites_discovered': sites,
                'summary': {
                    'total_alerts': len(alerts),
                    'high_risk': risk_summary['High'],
                    'medium_risk': risk_summary['Medium'],
                    'low_risk': risk_summary['Low'],
                    'info_risk': risk_summary['Informational']
                }
            }
            
            logger.info(f"Scan results compiled: {len(alerts)} alerts found")
            return results
            
        except Exception as e:
            logger.error(f"Failed to get scan results: {str(e)}")
            raise
    
    def stop_scan(self):
        """Stop all running scans"""
        try:
            self.scan_running = False
            if self.zap:
                # Stop all active scans
                active_scans = self.zap.ascan.scans()
                for scan in active_scans:
                    self.zap.ascan.stop(scan['id'])
                
                # Stop all spider scans
                spider_scans = self.zap.spider.scans()
                for scan in spider_scans:
                    self.zap.spider.stop(scan['id'])
                
                logger.info("All scans stopped")
        except Exception as e:
            logger.error(f"Error stopping scans: {str(e)}")
    
    def cleanup(self):
        """Clean up resources and stop ZAP"""
        try:
            self.stop_scan()
            if self.zap_manager:
                self.zap_manager.stop_zap()
            logger.info("ZAP scanner cleanup completed")
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
