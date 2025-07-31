# ZAP Security Scanner - Web Application

## Overview

This is a Flask-based web application that provides a user-friendly interface for conducting automated security scans using OWASP ZAP (Zed Attack Proxy). The application allows users to scan web applications for security vulnerabilities and generates comprehensive PDF reports of the findings.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Web Framework**: Flask with Jinja2 templating
- **UI Framework**: Bootstrap 5 with dark theme
- **JavaScript**: Vanilla JavaScript with polling-based real-time updates
- **Styling**: Custom CSS with Font Awesome icons
- **Real-time Updates**: AJAX polling for scan progress monitoring

### Backend Architecture
- **Web Framework**: Flask (Python)
- **Database ORM**: SQLAlchemy with Flask-SQLAlchemy
- **Database**: SQLite (configurable via environment variable)
- **Security Scanner**: OWASP ZAP integration via zapv2 Python library
- **Report Generation**: ReportLab for PDF report creation
- **Process Management**: Custom ZAP daemon lifecycle management

### Database Schema
- **ScanRecord Model**: Stores scan metadata, results, and status
  - Primary key, target URL, scan status
  - Timestamps for start/completion
  - JSON storage for vulnerability results
  - Error message logging

## Key Components

### Core Application (`app.py`)
- Flask application initialization and configuration
- Database setup and model integration
- Global scanner instance management
- Scan status tracking with in-memory state

### Scanner Module (`scanner.py`)
- ZAP scanner wrapper with enhanced functionality
- Handles ZAP daemon communication
- Configures scanning parameters
- Manages scan execution and progress tracking

### ZAP Manager (`zap_manager.py`)
- ZAP daemon lifecycle management
- Process startup, monitoring, and cleanup
- Connection validation and retry logic
- Cross-platform ZAP installation detection

### Report Generator (`report_generator.py`)
- Professional PDF report generation
- Custom styling for vulnerability severity levels
- Structured reporting with tables and charts
- Export functionality for scan results

### Database Models (`models.py`)
- SQLAlchemy models for data persistence
- Scan record tracking with status management
- JSON serialization for complex scan results
- Helper methods for duration calculation and UI styling

### Frontend Components
- **Base Template**: Common layout with Bootstrap navigation
- **Index Page**: Scan initiation form with URL validation
- **Results Page**: Real-time progress monitoring and results display
- **JavaScript Scanner**: AJAX-based polling for scan updates

## Data Flow

1. **Scan Initiation**: User submits target URL through web form
2. **ZAP Startup**: Application starts ZAP daemon if not running
3. **Database Record**: Creates scan record with "pending" status
4. **Background Scanning**: Executes spider and active scan phases
5. **Progress Updates**: Frontend polls backend for real-time status
6. **Result Processing**: Scan results parsed and stored in database
7. **Report Generation**: PDF reports created on-demand for completed scans

## External Dependencies

### Core Dependencies
- **Flask**: Web framework and routing
- **SQLAlchemy**: Database ORM and migrations
- **OWASP ZAP**: Security scanning engine (external process)
- **zapv2**: Python API client for ZAP communication
- **ReportLab**: PDF generation library
- **psutil**: Process management utilities

### Frontend Dependencies
- **Bootstrap 5**: UI framework with dark theme
- **Font Awesome**: Icon library
- **jQuery** (implied): For AJAX interactions

### System Requirements
- **OWASP ZAP**: Must be installed on the system
- **Python 3.x**: Runtime environment
- **SQLite**: Default database (configurable)

## Deployment Strategy

### Environment Configuration
- **DATABASE_URL**: Configurable database connection
- **SESSION_SECRET**: Flask session security key
- **ZAP_PATH**: Optional ZAP installation path override

### Production Considerations
- **WSGI**: Configured with ProxyFix for reverse proxy deployment
- **Database**: Supports PostgreSQL via environment variable
- **Logging**: Configurable logging levels
- **Security**: Session management and CSRF protection

### Container Deployment
- Application designed for containerized deployment
- External ZAP dependency requires special container considerations
- Volume mounting may be needed for persistent scan data

### Scaling Considerations
- Single-threaded ZAP scanning (one scan at a time)
- In-memory scan status (consider Redis for multi-instance)
- Database connection pooling configured
- Stateless design except for active scan tracking

The application follows a traditional MVC pattern with clear separation of concerns, making it maintainable and extensible for additional security scanning features.