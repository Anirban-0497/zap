class ScanManager {
    constructor() {
        this.scanStartTime = Date.now();
        this.updateInterval = null;
        this.isCompleted = false;
        this.authModalShown = false;
        
        this.initializeElements();
        this.startPolling();
        this.bindEvents();
    }
    
    initializeElements() {
        this.progressBar = document.getElementById('progressBar');
        this.progressPercent = document.getElementById('progressPercent');
        this.currentStatus = document.getElementById('currentStatus');
        this.elapsedTime = document.getElementById('elapsedTime');
        this.errorMessage = document.getElementById('errorMessage');
        this.errorText = document.getElementById('errorText');
        this.resultsCard = document.getElementById('resultsCard');
        this.stopScanBtn = document.getElementById('stopScanBtn');
        this.downloadReportBtn = document.getElementById('downloadReportBtn');
        this.viewDetailsBtn = document.getElementById('viewDetailsBtn');
        this.detailedResults = document.getElementById('detailedResults');
        this.vulnerabilityList = document.getElementById('vulnerabilityList');
        
        // Authentication elements
        this.authModal = document.getElementById('authModal');
        this.authForm = document.getElementById('authForm');
        this.authenticateBtn = document.getElementById('authenticateBtn');
        this.authError = document.getElementById('authError');
        this.authErrorText = document.getElementById('authErrorText');
        this.authSuccess = document.getElementById('authSuccess');
        this.authStatusCard = document.getElementById('authStatusCard');
        this.authenticatedUser = document.getElementById('authenticatedUser');
        
        // Result counters
        this.highRiskCount = document.getElementById('highRiskCount');
        this.mediumRiskCount = document.getElementById('mediumRiskCount');
        this.lowRiskCount = document.getElementById('lowRiskCount');
        this.totalAlertsCount = document.getElementById('totalAlertsCount');
    }
    
    bindEvents() {
        // Stop scan button
        if (this.stopScanBtn) {
            this.stopScanBtn.addEventListener('click', () => this.stopScan());
        }
        
        // Download report button
        if (this.downloadReportBtn) {
            this.downloadReportBtn.addEventListener('click', () => this.downloadReport());
        }
        
        // View details button
        if (this.viewDetailsBtn) {
            this.viewDetailsBtn.addEventListener('click', () => this.toggleDetailedResults());
        }
        
        // Authentication button
        if (this.authenticateBtn) {
            this.authenticateBtn.addEventListener('click', () => this.handleAuthentication());
        }
    }
    
    startPolling() {
        this.updateElapsedTime();
        this.fetchScanStatus();
        
        this.updateInterval = setInterval(() => {
            this.updateElapsedTime();
            if (!this.isCompleted) {
                this.fetchScanStatus();
            }
        }, 2000); // Poll every 2 seconds
    }
    
    async fetchScanStatus() {
        try {
            const response = await fetch('/api/scan_status');
            const data = await response.json();
            
            this.updateUI(data);
            
        } catch (error) {
            console.error('Error fetching scan status:', error);
            this.showError('Failed to fetch scan status');
        }
    }
    
    updateUI(scanStatus) {
        // Update progress
        const progress = Math.min(scanStatus.progress || 0, 100);
        this.progressBar.style.width = `${progress}%`;
        this.progressBar.setAttribute('aria-valuenow', progress);
        this.progressPercent.textContent = `${progress}%`;
        
        // Update status
        this.updateStatus(scanStatus.status || 'idle', scanStatus.running);
        
        // Handle errors
        if (scanStatus.error) {
            this.showError(scanStatus.error);
            this.isCompleted = true;
            this.stopPolling();
        }
        
        // Handle login form detection during spider phase
        if (scanStatus.spider_results && scanStatus.spider_results.login_detected && !this.authModalShown) {
            this.showAuthModal(scanStatus.spider_results.login_forms);
            this.authModalShown = true;
        }
        
        // Handle completion
        if (scanStatus.status === 'completed' && scanStatus.results) {
            this.handleScanCompletion(scanStatus);
        }
        
        // Show/hide stop button
        if (scanStatus.running) {
            this.stopScanBtn.style.display = 'inline-block';
        } else {
            this.stopScanBtn.style.display = 'none';
        }
    }
    
    updateStatus(status, isRunning) {
        const statusMap = {
            'idle': { class: 'bg-secondary', text: 'Idle' },
            'initializing': { class: 'bg-info', text: 'Initializing' },
            'starting_zap': { class: 'bg-info', text: 'Starting ZAP' },
            'crawling': { class: 'bg-primary', text: 'Crawling Website' },
            'active_scanning': { class: 'bg-warning', text: 'Security Scanning' },
            'generating_report': { class: 'bg-info', text: 'Generating Report' },
            'completed': { class: 'bg-success', text: 'Completed' },
            'error': { class: 'bg-danger', text: 'Error' },
            'stopped': { class: 'bg-warning', text: 'Stopped' }
        };
        
        const statusInfo = statusMap[status] || statusMap['idle'];
        this.currentStatus.className = `ms-2 badge ${statusInfo.class}`;
        this.currentStatus.textContent = statusInfo.text;
        
        // Animate progress bar for running scans
        if (isRunning) {
            this.progressBar.classList.add('progress-bar-striped', 'progress-bar-animated');
        } else {
            this.progressBar.classList.remove('progress-bar-striped', 'progress-bar-animated');
        }
    }
    
    handleScanCompletion(scanStatus) {
        this.isCompleted = true;
        this.stopPolling();
        
        // Update progress to 100%
        this.progressBar.style.width = '100%';
        this.progressPercent.textContent = '100%';
        
        // Show results
        this.displayResults(scanStatus.results);
        this.resultsCard.style.display = 'block';
        
        // Enable download button
        this.downloadReportBtn.disabled = false;
        
        // Auto-scroll to results
        this.resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    displayResults(results) {
        const riskSummary = results.risk_summary || {};
        
        // Update counters
        this.highRiskCount.textContent = riskSummary.High || 0;
        this.mediumRiskCount.textContent = riskSummary.Medium || 0;
        this.lowRiskCount.textContent = riskSummary.Low || 0;
        this.totalAlertsCount.textContent = results.alert_count || 0;
        
        // Store results for detailed view
        this.scanResults = results;
    }
    
    toggleDetailedResults() {
        if (this.detailedResults.style.display === 'none') {
            this.showDetailedResults();
            this.viewDetailsBtn.innerHTML = '<i class="fas fa-eye-slash me-2"></i>Hide Detailed Results';
        } else {
            this.detailedResults.style.display = 'none';
            this.viewDetailsBtn.innerHTML = '<i class="fas fa-eye me-2"></i>View Detailed Results';
        }
    }
    
    showDetailedResults() {
        if (!this.scanResults || !this.scanResults.alerts) {
            this.vulnerabilityList.innerHTML = '<p class="text-muted">No detailed results available.</p>';
            this.detailedResults.style.display = 'block';
            return;
        }
        
        const alerts = this.scanResults.alerts;
        let html = '';
        
        // Group alerts by risk level
        const riskLevels = ['High', 'Medium', 'Low', 'Informational'];
        
        riskLevels.forEach(riskLevel => {
            const riskAlerts = alerts.filter(alert => alert.risk === riskLevel);
            
            if (riskAlerts.length > 0) {
                const riskClass = this.getRiskClass(riskLevel);
                html += `
                    <div class="mb-4">
                        <h6 class="text-${riskClass}">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            ${riskLevel} Risk (${riskAlerts.length})
                        </h6>
                        <div class="row">
                `;
                
                riskAlerts.forEach((alert, index) => {
                    html += `
                        <div class="col-md-6 mb-3">
                            <div class="card border-${riskClass}">
                                <div class="card-body">
                                    <h6 class="card-title text-${riskClass}">${this.escapeHtml(alert.name || 'Unknown Vulnerability')}</h6>
                                    <p class="card-text small">${this.escapeHtml(alert.description || 'No description available').substring(0, 150)}...</p>
                                    <div class="small text-muted">
                                        <div><strong>URL:</strong> ${this.escapeHtml(alert.url || 'N/A')}</div>
                                        <div><strong>Confidence:</strong> ${this.escapeHtml(alert.confidence || 'Unknown')}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                html += '</div></div>';
            }
        });
        
        if (html === '') {
            html = '<p class="text-success"><i class="fas fa-check-circle me-2"></i>No vulnerabilities found!</p>';
        }
        
        this.vulnerabilityList.innerHTML = html;
        this.detailedResults.style.display = 'block';
    }
    
    getRiskClass(riskLevel) {
        const riskClasses = {
            'High': 'danger',
            'Medium': 'warning',
            'Low': 'info',
            'Informational': 'secondary'
        };
        return riskClasses[riskLevel] || 'secondary';
    }
    
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
    
    updateElapsedTime() {
        const elapsed = Date.now() - this.scanStartTime;
        const hours = Math.floor(elapsed / 3600000);
        const minutes = Math.floor((elapsed % 3600000) / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        
        const timeString = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        this.elapsedTime.textContent = timeString;
    }
    
    async stopScan() {
        if (confirm('Are you sure you want to stop the current scan?')) {
            try {
                const response = await fetch('/api/stop_scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                const result = await response.json();
                
                if (result.success) {
                    this.isCompleted = true;
                    this.stopPolling();
                    this.updateStatus('stopped', false);
                    this.showError('Scan stopped by user', 'warning');
                } else {
                    this.showError(result.message || 'Failed to stop scan');
                }
                
            } catch (error) {
                console.error('Error stopping scan:', error);
                this.showError('Failed to stop scan');
            }
        }
    }
    
    downloadReport() {
        console.log('Download report button clicked');
        
        // Show loading state on download button
        if (this.downloadReportBtn) {
            this.downloadReportBtn.disabled = true;
            this.downloadReportBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Preparing Download...';
        }
        
        // First try to get scan ID from current scan status
        fetch('/api/scan_status')
            .then(response => {
                console.log('Scan status response received:', response.status);
                return response.json();
            })
            .then(data => {
                console.log('Scan status data:', data); // Debug log
                if (data.scan_id) {
                    console.log(`Downloading report for scan ID: ${data.scan_id}`); // Debug log
                    this.initiateDownload(data.scan_id);
                } else {
                    // If no scan_id in status, try to get the latest completed scan
                    console.log('No scan_id in status, trying to get latest completed scan');
                    fetch('/api/latest_scan_id')
                        .then(response => {
                            console.log('Latest scan ID response:', response.status);
                            return response.json();
                        })
                        .then(data => {
                            console.log('Latest scan data:', data);
                            if (data.scan_id) {
                                console.log(`Downloading report for latest scan ID: ${data.scan_id}`);
                                this.initiateDownload(data.scan_id);
                            } else {
                                console.error('No completed scans found');
                                this.showError('No completed scans available for download. Please ensure the scan completed successfully.');
                                this.resetDownloadButton();
                            }
                        })
                        .catch(error => {
                            console.error('Error getting latest scan ID:', error);
                            this.showError('Failed to get scan information. Please try running a new scan.');
                            this.resetDownloadButton();
                        });
                }
            })
            .catch(error => {
                console.error('Error getting scan ID:', error);
                this.showError('Failed to download report');
                this.resetDownloadButton();
            });
    }
    
    initiateDownload(scanId) {
        console.log(`Initiating download for scan ID: ${scanId}`);
        
        // Create download URL
        const downloadUrl = `/download_report/${scanId}`;
        console.log(`Download URL: ${downloadUrl}`);
        
        // Create a temporary link and click it to trigger download
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = `security_report_${scanId}.pdf`;
        link.style.display = 'none';
        document.body.appendChild(link);
        
        // Add event listeners to handle success/failure
        link.addEventListener('click', () => {
            console.log('Download link clicked');
            // Remove the link after a short delay
            setTimeout(() => {
                if (document.body.contains(link)) {
                    document.body.removeChild(link);
                }
            }, 1000);
        });
        
        // Test the endpoint first
        fetch(downloadUrl, { method: 'HEAD' })
            .then(response => {
                console.log(`Download endpoint check: ${response.status}`);
                if (response.ok) {
                    console.log('Endpoint is working, triggering download...');
                    link.click();
                    this.resetDownloadButton();
                } else {
                    console.error(`Server returned ${response.status}`);
                    this.showError(`Download failed: Server returned ${response.status}. Check that the scan completed successfully.`);
                    if (document.body.contains(link)) {
                        document.body.removeChild(link);
                    }
                    this.resetDownloadButton();
                }
            })
            .catch(error => {
                console.error('Download check failed:', error);
                // Still try the download as fallback
                console.log('Attempting download despite check failure');
                link.click();
                this.resetDownloadButton();
            });
    }
    
    showError(message, type = 'danger') {
        this.errorText.textContent = message;
        this.errorMessage.className = `alert alert-${type} mt-3`;
        this.errorMessage.style.display = 'block';
        
        // Auto-hide after 5 seconds for warnings
        if (type === 'warning') {
            setTimeout(() => {
                this.errorMessage.style.display = 'none';
            }, 5000);
        }
    }
    
    stopPolling() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    }
    
    resetDownloadButton() {
        if (this.downloadReportBtn) {
            this.downloadReportBtn.disabled = false;
            this.downloadReportBtn.innerHTML = '<i class="fas fa-download me-2"></i>Download PDF Report';
        }
    }
    
    showAuthModal(loginForms) {
        console.log('Login forms detected:', loginForms);
        if (this.authModal) {
            // Show the authentication modal using Bootstrap
            const modal = new bootstrap.Modal(this.authModal);
            modal.show();
        }
    }
    
    async handleAuthentication() {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        
        if (!username || !password) {
            this.showAuthError('Please enter both username and password');
            return;
        }
        
        // Show loading state
        this.authenticateBtn.disabled = true;
        this.authenticateBtn.innerHTML = '<i class="fas fa-spinner fa-pulse me-2"></i>Authenticating...';
        this.hideAuthMessages();
        
        try {
            const response = await fetch('/api/authenticate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showAuthSuccess();
                this.showAuthStatusCard(username);
                
                // Close modal after 2 seconds
                setTimeout(() => {
                    const modal = bootstrap.Modal.getInstance(this.authModal);
                    if (modal) modal.hide();
                }, 2000);
                
            } else {
                this.showAuthError(result.message || 'Authentication failed');
            }
            
        } catch (error) {
            console.error('Authentication error:', error);
            this.showAuthError('Network error during authentication');
        } finally {
            // Reset button state
            this.authenticateBtn.disabled = false;
            this.authenticateBtn.innerHTML = '<i class="fas fa-sign-in-alt me-2"></i>Authenticate';
        }
    }
    
    showAuthError(message) {
        this.authErrorText.textContent = message;
        this.authError.style.display = 'block';
        this.authSuccess.style.display = 'none';
    }
    
    showAuthSuccess() {
        this.authSuccess.style.display = 'block';
        this.authError.style.display = 'none';
    }
    
    hideAuthMessages() {
        this.authError.style.display = 'none';
        this.authSuccess.style.display = 'none';
    }
    
    showAuthStatusCard(username) {
        if (this.authenticatedUser) {
            this.authenticatedUser.textContent = username;
        }
        if (this.authStatusCard) {
            this.authStatusCard.style.display = 'block';
        }
    }
}

// Initialize scan manager when page loads
document.addEventListener('DOMContentLoaded', function() {
    new ScanManager();
});
