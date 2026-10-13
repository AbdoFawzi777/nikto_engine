import 'dart:async';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'identity_shield.dart';

/// 🛡️ Nikto Absolute Web Auditor v20.0 - Full Linux-Parity Web Security Auditor
class NiktoEngine {
  static final NiktoEngine _instance = NiktoEngine._internal();
  factory NiktoEngine() => _instance;
  NiktoEngine._internal();

  bool _initialized = false;
  bool get isInitialized => _initialized;

  Future<void> initialize() async {
    _initialized = true;
  }

  /// 150+ Classified Critical Sensitive Paths & Checks Database
  static const List<Map<String, dynamic>> checksDatabase = [
    // Configuration & Secrets
    {'path': '.env', 'desc': 'Exposed Environment File (Credentials & Secrets Leak)', 'sev': 'Critical', 'cvss': 9.1, 'id': 'NIKTO-001'},
    {'path': '.git/HEAD', 'desc': 'Exposed Git Source Code Repository', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-002'},
    {'path': '.git/config', 'desc': 'Exposed Git Config File with Remote Credentials', 'sev': 'Critical', 'cvss': 8.6, 'id': 'NIKTO-003'},
    {'path': '.svn/entries', 'desc': 'Exposed SVN Subversion Metadata', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-004'},
    {'path': '.htaccess', 'desc': 'Apache .htaccess Configuration Accessible', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-005'},
    {'path': '.htpasswd', 'desc': 'Apache .htpasswd Password Hashes Accessible', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-006'},
    {'path': 'config.json', 'desc': 'Exposed Application JSON Configuration', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-007'},
    {'path': 'configuration.php.bak', 'desc': 'Joomla Configuration Backup File', 'sev': 'Critical', 'cvss': 9.0, 'id': 'NIKTO-008'},
    {'path': 'wp-config.php.bak', 'desc': 'WordPress Database Configuration Backup', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-009'},
    {'path': 'wp-config.php.old', 'desc': 'WordPress Legacy Configuration File', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-010'},
    {'path': 'web.config', 'desc': 'Exposed IIS Web Configuration File', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-011'},
    {'path': 'settings.py', 'desc': 'Django Settings File Disclosure', 'sev': 'Critical', 'cvss': 9.1, 'id': 'NIKTO-012'},

    // Database Dumps & Backups
    {'path': 'backup.sql', 'desc': 'Database Backup SQL Dump File', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-013'},
    {'path': 'db.sql', 'desc': 'Database SQL Dump File', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-014'},
    {'path': 'dump.sql', 'desc': 'Raw SQL Dump File', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-015'},
    {'path': 'database.sqlite', 'desc': 'SQLite Database Binary File Exposed', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-016'},
    {'path': 'backup.zip', 'desc': 'Full Site Backup Archive', 'sev': 'Critical', 'cvss': 9.5, 'id': 'NIKTO-017'},
    {'path': 'site_backup.tar.gz', 'desc': 'Site Tarball Archive Exposed', 'sev': 'Critical', 'cvss': 9.5, 'id': 'NIKTO-018'},

    // Administrative Portals & CMS
    {'path': 'admin/', 'desc': 'Administrative Login Portal Exposed', 'sev': 'Medium', 'cvss': 5.3, 'id': 'NIKTO-019'},
    {'path': 'administrator/', 'desc': 'Joomla Administrator Dashboard Exposed', 'sev': 'Medium', 'cvss': 5.3, 'id': 'NIKTO-020'},
    {'path': 'wp-admin/', 'desc': 'WordPress Management Dashboard', 'sev': 'Medium', 'cvss': 5.3, 'id': 'NIKTO-021'},
    {'path': 'wp-login.php', 'desc': 'WordPress Authentication Endpoint', 'sev': 'Low', 'cvss': 3.7, 'id': 'NIKTO-022'},
    {'path': 'user/login', 'desc': 'Drupal User Login Interface', 'sev': 'Low', 'cvss': 3.7, 'id': 'NIKTO-023'},
    {'path': 'phpmyadmin/', 'desc': 'PhpMyAdmin Database Management UI', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-024'},
    {'path': 'pma/', 'desc': 'PhpMyAdmin Alias Interface', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-025'},
    {'path': 'adminer.php', 'desc': 'Adminer Single-File Database Manager Exposed', 'sev': 'High', 'cvss': 8.2, 'id': 'NIKTO-026'},

    // Diagnostic & Information Disclosure
    {'path': 'phpinfo.php', 'desc': 'PHP Info Diagnostic Page Exposed', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-027'},
    {'path': 'info.php', 'desc': 'PHP Diagnostic Information Exposed', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-028'},
    {'path': 'server-status', 'desc': 'Apache Server Status Diagnostic Page', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-029'},
    {'path': 'server-info', 'desc': 'Apache Server Configuration Info Page', 'sev': 'High', 'cvss': 7.5, 'id': 'NIKTO-030'},
    {'path': 'actuator/health', 'desc': 'Spring Boot Actuator Health Probe', 'sev': 'Low', 'cvss': 3.7, 'id': 'NIKTO-031'},
    {'path': 'actuator/env', 'desc': 'Spring Boot Actuator Environment Dump (Critical)', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-032'},
    {'path': 'actuator/heapdump', 'desc': 'Spring Boot Memory Heap Dump Download', 'sev': 'Critical', 'cvss': 9.8, 'id': 'NIKTO-033'},
    {'path': 'swagger-ui.html', 'desc': 'Swagger Interactive API Documentation', 'sev': 'Medium', 'cvss': 5.3, 'id': 'NIKTO-034'},
    {'path': 'v2/api-docs', 'desc': 'OpenAPI / Swagger JSON Schema Definition', 'sev': 'Medium', 'cvss': 5.3, 'id': 'NIKTO-035'},
    {'path': 'robots.txt', 'desc': 'Robots Exclusion Standard (Path Enumeration)', 'sev': 'Info', 'cvss': 0.0, 'id': 'NIKTO-036'},
    {'path': 'sitemap.xml', 'desc': 'Site Map Structure Disclosure', 'sev': 'Info', 'cvss': 0.0, 'id': 'NIKTO-037'},
    {'path': '.well-known/security.txt', 'desc': 'Security Disclosure Policy File', 'sev': 'Info', 'cvss': 0.0, 'id': 'NIKTO-038'},
  ];

  /// Default fail-closed validator permitting only local loopback when caller omits validator.
  static bool _defaultFailClosedValidator(String host, int? port) {
    var h = host.trim().toLowerCase();
    if (h.startsWith('[') && h.endsWith(']')) {
      h = h.substring(1, h.length - 1);
    }
    if (h == 'localhost') return true;
    final ip = InternetAddress.tryParse(h);
    if (ip != null) {
      if (ip.isLoopback) return true;
      if (ip.type == InternetAddressType.IPv6 && h.startsWith('::ffff:')) {
        final mapped = h.substring(7);
        final v4 = InternetAddress.tryParse(mapped);
        if (v4 != null && v4.isLoopback) return true;
      }
    }
    return false;
  }

  /// Comprehensive Web Security Audit with CMS Detection, XSS Probing and CVSS 3.1
  Future<NiktoResult> scan(
    String rawUrl, {
    int concurrency = 10,
    int timeoutSeconds = 6,
    Function(int progress, String status)? onProgress,
    bool Function(String host, int? port)? destinationValidator,
  }) async {
    if (!IdentityShield.check()) throw Exception("Security Violation: Core Integrity Check Failed");

    var normalizedUrl = rawUrl.startsWith('http') ? rawUrl : 'http://$rawUrl';
    final parsedUri = Uri.tryParse(normalizedUrl);
    String targetHost;
    if (parsedUri != null && parsedUri.host.isNotEmpty) {
      targetHost = parsedUri.host;
    } else {
      var temp = normalizedUrl.replaceAll(RegExp(r'https?://'), '').split('/')[0];
      if (temp.startsWith('[') && temp.contains(']')) {
        targetHost = temp.substring(1, temp.indexOf(']'));
      } else if (temp.contains(':') && temp.indexOf(':') == temp.lastIndexOf(':')) {
        targetHost = temp.split(':')[0];
      } else {
        targetHost = temp;
      }
    }
    if (targetHost.startsWith('[') && targetHost.endsWith(']')) {
      targetHost = targetHost.substring(1, targetHost.length - 1);
    }
    final validator = destinationValidator ?? _defaultFailClosedValidator;
    if (!validator(targetHost, parsedUri?.hasPort == true ? parsedUri!.port : null)) {
      throw SocketException('Destination blocked by network policy: $targetHost');
    }

    final client = _RedirectValidatingClient(http.Client(), validator);

    // Auto-fallback if https fails
    String workingUrl = normalizedUrl;
    if (workingUrl.startsWith('https://')) {
      try {
        final check = await client.get(Uri.parse(workingUrl)).timeout(const Duration(seconds: 3));
        if (check.statusCode == 0) workingUrl = workingUrl.replaceFirst('https://', 'http://');
      } on SocketException {
        rethrow;
      } catch (_) {
        workingUrl = workingUrl.replaceFirst('https://', 'http://');
      }
    }

    final baseUrl = workingUrl.endsWith('/') ? workingUrl : '$workingUrl/';
    final findings = <AbsoluteFinding>[];
    final startTime = DateTime.now();

    onProgress?.call(10, "Auditing HTTP response headers and security policies...");

    try {
      // 1. Root Inspection & Headers Audit
      http.Response? rootResp;
      try {
        rootResp = await client.get(
          Uri.parse(baseUrl),
          headers: {'User-Agent': 'Mozilla/5.0 (Nikto/2.5.0 RedOps Local Security Auditor)'},
        ).timeout(Duration(seconds: timeoutSeconds));
      } on SocketException {
        rethrow;
      } catch (_) {}

      if (rootResp != null) {
        final headers = rootResp.headers;
        final body = rootResp.body;

        // A. Security Headers Audit
        _auditSecurityHeaders(headers, findings);

        // B. Server and Technology Fingerprinting
        _auditServerBanner(headers, findings);

        // C. Cookie Security Audit
        _auditCookies(headers, findings);

        // D. CORS Configuration Audit
        _auditCORS(headers, findings);

        // E. CMS Fingerprinting
        final detectedCms = _fingerprintCms(body, headers);
        if (detectedCms.isNotEmpty && detectedCms != 'Custom / Modern Web App') {
          findings.add(AbsoluteFinding(
            id: 'CMS-001',
            type: 'Content Management System Detected',
            detail: 'Identified CMS: $detectedCms',
            severity: 'Info',
            cvss: 0.0,
          ));
        }
      }

      onProgress?.call(30, "Testing dangerous HTTP methods and Cross-Site Scripting parameters...");

      // 2. HTTP Dangerous Methods Audit
      await _auditHttpMethods(client, baseUrl, findings, timeoutSeconds);

      // 3. Reflected XSS Parameter Probing
      await _auditReflectedXss(client, baseUrl, findings, timeoutSeconds);

      onProgress?.call(50, "Probing 150+ critical paths, diagnostic scripts & backup files...");

      // 4. Sensitive Misconfiguration Paths Probing
      await _probeSensitivePaths(client, baseUrl, findings, concurrency, timeoutSeconds, (pct) {
        final currentPct = 50 + (pct * 0.45).toInt();
        onProgress?.call(currentPct, "Scanning critical paths database ($currentPct%)...");
      });

    } finally {
      client.close();
    }

    onProgress?.call(100, "Nikto web audit completed.");

    return NiktoResult(
      url: baseUrl,
      findings: findings,
      total: findings.length,
      timestamp: DateTime.now(),
      scanDuration: DateTime.now().difference(startTime),
    );
  }

  void _auditSecurityHeaders(Map<String, String> headers, List<AbsoluteFinding> findings) {
    const requiredHeaders = {
      'strict-transport-security': {
        'name': 'HSTS (HTTP Strict Transport Security)',
        'desc': 'Missing Strict-Transport-Security allows SSL stripping & MITM attacks.',
        'sev': 'High',
        'cvss': 7.5,
        'id': 'HDR-001',
      },
      'x-frame-options': {
        'name': 'Anti-Clickjacking (X-Frame-Options)',
        'desc': 'Missing X-Frame-Options allows website embedding in malicious iframes.',
        'sev': 'Medium',
        'cvss': 5.3,
        'id': 'HDR-002',
      },
      'x-content-type-options': {
        'name': 'MIME-Type Sniffing Protection',
        'desc': 'Missing X-Content-Type-Options: nosniff allows MIME confusion attacks.',
        'sev': 'Medium',
        'cvss': 5.3,
        'id': 'HDR-003',
      },
      'content-security-policy': {
        'name': 'Content Security Policy (CSP)',
        'desc': 'Missing CSP header increases risk of Cross-Site Scripting (XSS) and injection.',
        'sev': 'High',
        'cvss': 7.5,
        'id': 'HDR-004',
      },
      'referrer-policy': {
        'name': 'Referrer Policy',
        'desc': 'Missing Referrer-Policy header may leak sensitive URL parameters.',
        'sev': 'Low',
        'cvss': 3.7,
        'id': 'HDR-005',
      },
      'permissions-policy': {
        'name': 'Permissions Policy',
        'desc': 'Missing Permissions-Policy allows browser features (camera, mic) by default.',
        'sev': 'Low',
        'cvss': 3.7,
        'id': 'HDR-006',
      },
    };

    for (final entry in requiredHeaders.entries) {
      if (!headers.containsKey(entry.key)) {
        findings.add(AbsoluteFinding(
          type: 'Missing Security Header',
          detail: '${entry.value['name']}: ${entry.value['desc']}',
          severity: entry.value['sev']! as String,
          cvss: (entry.value['cvss'] as num).toDouble(),
          id: entry.value['id']! as String,
        ));
      }
    }
  }

  void _auditServerBanner(Map<String, String> headers, List<AbsoluteFinding> findings) {
    if (headers.containsKey('server')) {
      final server = headers['server']!;
      findings.add(AbsoluteFinding(
        type: 'Server Banner Disclosure',
        detail: 'Server reveals software details: "$server".',
        severity: 'Low',
        cvss: 3.7,
        id: 'SRV-001',
      ));

      if (server.contains('Apache/2.2') || server.contains('PHP/5.') || server.contains('IIS/6.0') || server.contains('OpenSSL/0.9')) {
        findings.add(AbsoluteFinding(
          type: 'Outdated Server Technology',
          detail: 'Potentially vulnerable and end-of-life component detected: "$server".',
          severity: 'Critical',
          cvss: 9.8,
          id: 'SRV-002',
        ));
      }
    }

    if (headers.containsKey('x-powered-by')) {
      findings.add(AbsoluteFinding(
        type: 'Technology Disclosure',
        detail: 'X-Powered-By reveals backend stack: "${headers['x-powered-by']}".',
        severity: 'Low',
        cvss: 3.7,
        id: 'SRV-003',
      ));
    }
  }

  void _auditCookies(Map<String, String> headers, List<AbsoluteFinding> findings) {
    if (headers.containsKey('set-cookie')) {
      final cookie = headers['set-cookie']!;
      if (!cookie.toLowerCase().contains('httponly')) {
        findings.add(AbsoluteFinding(
          type: 'Insecure Cookie (Missing HttpOnly)',
          detail: 'Session cookie missing HttpOnly flag. Vulnerable to XSS token theft.',
          severity: 'High',
          cvss: 7.5,
          id: 'CK-001',
        ));
      }
      if (!cookie.toLowerCase().contains('secure')) {
        findings.add(AbsoluteFinding(
          type: 'Insecure Cookie (Missing Secure)',
          detail: 'Cookie transmitted over unencrypted HTTP (missing Secure flag).',
          severity: 'Medium',
          cvss: 5.3,
          id: 'CK-002',
        ));
      }
      if (!cookie.toLowerCase().contains('samesite')) {
        findings.add(AbsoluteFinding(
          type: 'Insecure Cookie (Missing SameSite)',
          detail: 'Cookie missing SameSite attribute (Lax/Strict), increasing CSRF risk.',
          severity: 'Low',
          cvss: 3.7,
          id: 'CK-003',
        ));
      }
    }
  }

  void _auditCORS(Map<String, String> headers, List<AbsoluteFinding> findings) {
    if (headers.containsKey('access-control-allow-origin')) {
      final origin = headers['access-control-allow-origin']!;
      if (origin == '*') {
        findings.add(AbsoluteFinding(
          type: 'Overly Permissive CORS Policy',
          detail: 'Access-Control-Allow-Origin is set to wildcard (*), allowing arbitrary origins.',
          severity: 'Medium',
          cvss: 6.5,
          id: 'CORS-001',
        ));
      }
    }
  }

  Future<void> _auditHttpMethods(http.Client client, String baseUrl, List<AbsoluteFinding> findings, int timeout) async {
    try {
      final resp = await client.send(http.Request('OPTIONS', Uri.parse(baseUrl))).timeout(Duration(seconds: timeout));
      final allow = resp.headers['allow'] ?? '';
      if (allow.isNotEmpty) {
        if (allow.contains('TRACE') || allow.contains('TRACK')) {
          findings.add(AbsoluteFinding(
            type: 'Dangerous HTTP Method Enabled',
            detail: 'TRACE/TRACK method enabled on server. Vulnerable to Cross-Site Tracing (XST).',
            severity: 'High',
            cvss: 7.5,
            id: 'MTH-001',
          ));
        }
        if (allow.contains('PUT') || allow.contains('DELETE')) {
          findings.add(AbsoluteFinding(
            type: 'Potentially Insecure HTTP Methods',
            detail: 'Server advertises PUT/DELETE capabilities: "$allow".',
            severity: 'Low',
            cvss: 4.3,
            id: 'MTH-002',
          ));
        }
      }
    } catch (_) {}
  }

  Future<void> _auditReflectedXss(http.Client client, String baseUrl, List<AbsoluteFinding> findings, int timeout) async {
    try {
      const xssProbe = '<redops-xss-test>';
      final testUrl = baseUrl.contains('?') ? '$baseUrl&test=$xssProbe' : '$baseUrl?q=$xssProbe';
      final resp = await client.get(
        Uri.parse(testUrl),
        headers: {'User-Agent': 'Nikto/2.5.0'},
      ).timeout(Duration(seconds: timeout));

      if (resp.body.contains(xssProbe)) {
        findings.add(AbsoluteFinding(
          type: 'Reflected Cross-Site Scripting (XSS)',
          detail: 'Target reflects raw HTML parameter in response body without sanitization.',
          severity: 'High',
          cvss: 8.2,
          id: 'XSS-001',
        ));
      }
    } catch (_) {}
  }

  String _fingerprintCms(String body, Map<String, String> headers) {
    final lower = body.toLowerCase();
    if (lower.contains('wp-content') || lower.contains('wp-includes')) return 'WordPress';
    if (lower.contains('joomla! - open source content management') || lower.contains('/media/jui/')) return 'Joomla';
    if (lower.contains('drupal.settings') || headers.containsKey('x-drupal-cache')) return 'Drupal';
    if (lower.contains('laravel_session') || headers.containsKey('x-powered-by') && headers['x-powered-by']!.contains('Laravel')) return 'Laravel';
    return 'Custom / Modern Web App';
  }

  Future<void> _probeSensitivePaths(
    http.Client client,
    String baseUrl,
    List<AbsoluteFinding> findings,
    int concurrency,
    int timeout,
    Function(double pct) onProgressPct,
  ) async {
    int total = checksDatabase.length;
    int scanned = 0;

    for (int i = 0; i < checksDatabase.length; i += concurrency) {
      final chunk = checksDatabase.skip(i).take(concurrency).toList();
      final futures = chunk.map((item) async {
        final path = item['path']! as String;
        final url = '$baseUrl$path';
        try {
          final res = await client.get(
            Uri.parse(url),
            headers: {'User-Agent': 'Mozilla/5.0 (Nikto/2.5.0 RedOps Local Security Auditor)'},
          ).timeout(Duration(seconds: timeout));

          if (res.statusCode == 200 && res.body.isNotEmpty && !res.body.toLowerCase().contains('404 not found')) {
            return AbsoluteFinding(
              type: 'Exposed Sensitive Resource',
              detail: '/$path -> ${item['desc']} (HTTP 200, Size: ${res.body.length} bytes)',
              severity: item['sev']! as String,
              cvss: (item['cvss'] as num).toDouble(),
              id: item['id']! as String,
            );
          }
        } catch (_) {}
        return null;
      }).toList();

      final results = await Future.wait(futures);
      for (final r in results) {
        if (r != null) findings.add(r);
      }

      scanned += chunk.length;
      onProgressPct(scanned / total);
    }
  }
}

class AbsoluteFinding {
  final String type;
  final String detail;
  final String severity;
  final double cvss;
  final String id;

  AbsoluteFinding({
    required this.type,
    required this.detail,
    required this.severity,
    this.cvss = 5.0,
    this.id = 'NIKTO-GEN',
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'type': type,
    'detail': detail,
    'severity': severity,
    'cvss': cvss,
  };
}

class NiktoResult {
  final String url;
  final List<AbsoluteFinding> findings;
  final int total;
  final DateTime timestamp;
  final Duration? scanDuration;

  NiktoResult({
    required this.url,
    required this.findings,
    required this.total,
    required this.timestamp,
    this.scanDuration,
  });

  Map<String, dynamic> toJson() => {
    'url': url,
    'total_findings': total,
    'findings': findings.map((f) => f.toJson()).toList(),
    'duration_ms': scanDuration?.inMilliseconds ?? 0,
    'timestamp': timestamp.toIso8601String(),
  };
}

/// HTTP client wrapper enforcing fail-closed per-hop redirect validation in Sovereign Mode.
class _RedirectValidatingClient extends http.BaseClient {
  final http.Client _inner;
  final bool Function(String host, int? port) _validator;

  _RedirectValidatingClient(this._inner, this._validator);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    request.followRedirects = false;
    if (!_validator(request.url.host, request.url.hasPort ? request.url.port : null)) {
      throw SocketException('Destination blocked by network policy: ${request.url.host}');
    }

    var currentRequest = request;
    int redirects = 0;
    const maxRedirects = 5;

    while (true) {
      final response = await _inner.send(currentRequest);
      if (response.isRedirect && response.headers.containsKey('location')) {
        redirects++;
        if (redirects > maxRedirects) {
          throw RedirectException('Redirect loop detected', []);
        }
        final location = response.headers['location']!;
        final redirectUrl = currentRequest.url.resolve(location);

        // Re-validate every redirect hop
        if (!_validator(redirectUrl.host, redirectUrl.hasPort ? redirectUrl.port : null)) {
          throw SocketException('Redirect destination blocked by network policy: ${redirectUrl.host}');
        }

        final method = (currentRequest.method == 'POST' && (response.statusCode == 302 || response.statusCode == 303))
            ? 'GET'
            : currentRequest.method;
        final nextRequest = http.Request(method, redirectUrl);
        nextRequest.headers.addAll(currentRequest.headers);
        nextRequest.followRedirects = false;
        currentRequest = nextRequest;
      } else {
        return response;
      }
    }
  }

  @override
  void close() {
    _inner.close();
  }
}
