import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'identity_shield.dart';

/// 🛡️ Nikto Web Vulnerability Engine v8.0 - Comprehensive Local Security Auditor
class NiktoEngine {
  static final NiktoEngine _instance = NiktoEngine._internal();
  factory NiktoEngine() => _instance;
  NiktoEngine._internal();

  bool _initialized = false;
  bool get isInitialized => _initialized;

  Future<void> initialize() async {
    _initialized = true;
  }

  /// List of critical sensitive paths to audit for misconfigurations
  static const List<Map<String, String>> sensitivePaths = [
    {'path': '.env', 'desc': 'Exposed Environment File (Credentials Leak)', 'severity': 'Critical'},
    {'path': '.git/HEAD', 'desc': 'Exposed Git Source Code Repository', 'severity': 'Critical'},
    {'path': '.git/config', 'desc': 'Exposed Git Config File', 'severity': 'Critical'},
    {'path': '.svn/entries', 'desc': 'Exposed SVN Repository', 'severity': 'High'},
    {'path': '.DS_Store', 'desc': 'Exposed macOS Metadata File', 'severity': 'Medium'},
    {'path': 'robots.txt', 'desc': 'Information Disclosure in Robots.txt', 'severity': 'Info'},
    {'path': 'sitemap.xml', 'desc': 'Sitemap Disclosure', 'severity': 'Info'},
    {'path': '.well-known/security.txt', 'desc': 'Security Disclosure Policy File', 'severity': 'Info'},
    {'path': 'phpinfo.php', 'desc': 'Exposed PHP Configuration (phpinfo)', 'severity': 'High'},
    {'path': 'info.php', 'desc': 'Exposed PHP Info Script', 'severity': 'High'},
    {'path': 'server-status', 'desc': 'Exposed Apache/Nginx Server Status', 'severity': 'High'},
    {'path': 'server-info', 'desc': 'Exposed Server Info Module', 'severity': 'High'},
    {'path': 'wp-config.php.bak', 'desc': 'WordPress Database Backup File', 'severity': 'Critical'},
    {'path': 'config.json', 'desc': 'Exposed JSON Configuration File', 'severity': 'High'},
    {'path': 'web.config', 'desc': 'Exposed IIS Configuration File', 'severity': 'High'},
    {'path': 'backup.sql', 'desc': 'Exposed Database SQL Dump', 'severity': 'Critical'},
    {'path': 'db.sql', 'desc': 'Exposed Database SQL Dump', 'severity': 'Critical'},
    {'path': 'admin/', 'desc': 'Administrative Panel Exposed', 'severity': 'Medium'},
    {'path': 'phpmyadmin/', 'desc': 'PhpMyAdmin Database Interface Exposed', 'severity': 'High'},
    {'path': 'pma/', 'desc': 'PhpMyAdmin Alias Exposed', 'severity': 'High'},
    {'path': 'actuator/health', 'desc': 'Spring Boot Actuator Health Endpoint', 'severity': 'Low'},
    {'path': 'actuator/env', 'desc': 'Spring Boot Actuator Environment Dump', 'severity': 'Critical'},
    {'path': 'swagger-ui.html', 'desc': 'Swagger API Documentation Interface', 'severity': 'Medium'},
    {'path': 'api-docs', 'desc': 'OpenAPI / Swagger Documentation', 'severity': 'Medium'},
  ];

  /// Comprehensive Local Security Audit
  Future<NiktoResult> scan(String rawUrl, {int concurrency = 8, int timeoutSeconds = 6}) async {
    if (!IdentityShield.check()) throw Exception("Security Violation: Core Integrity Check Failed");

    final normalizedUrl = rawUrl.startsWith('http') ? rawUrl : 'http://$rawUrl';
    final baseUrl = normalizedUrl.endsWith('/') ? normalizedUrl : '$normalizedUrl/';
    final findings = <AbsoluteFinding>[];
    final client = http.Client();
    final startTime = DateTime.now();

    try {
      // 1. Initial Root Inspection & Headers Audit
      http.Response? rootResp;
      try {
        rootResp = await client.get(
          Uri.parse(baseUrl),
          headers: {'User-Agent': 'Nikto/2.5.0 (RedOps Hub Local Security Auditor)'},
        ).timeout(Duration(seconds: timeoutSeconds));
      } catch (_) {}

      if (rootResp != null) {
        final headers = rootResp.headers;

        // A. Security Headers Audit
        _auditSecurityHeaders(headers, findings);

        // B. Server and Technology Fingerprinting
        _auditServerBanner(headers, findings);

        // C. Cookie Security Audit
        _auditCookies(headers, findings);

        // D. CORS Configuration Audit
        _auditCORS(headers, findings);
      }

      // 2. HTTP Dangerous Methods Audit
      await _auditHttpMethods(client, baseUrl, findings, timeoutSeconds);

      // 3. Sensitive Misconfiguration Paths Probing
      await _probeSensitivePaths(client, baseUrl, findings, concurrency, timeoutSeconds);

    } finally {
      client.close();
    }

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
        'desc': 'Missing Strict-Transport-Security header allows potential SSL stripping & MITM attacks.',
        'sev': 'High'
      },
      'x-frame-options': {
        'name': 'Anti-Clickjacking (X-Frame-Options)',
        'desc': 'Missing X-Frame-Options allows website embedding in malicious iframes (Clickjacking).',
        'sev': 'Medium'
      },
      'x-content-type-options': {
        'name': 'MIME-Type Sniffing Protection',
        'desc': 'Missing X-Content-Type-Options: nosniff allows MIME confusion and drive-by attacks.',
        'sev': 'Medium'
      },
      'content-security-policy': {
        'name': 'Content Security Policy (CSP)',
        'desc': 'Missing CSP header increases risk of Cross-Site Scripting (XSS) and data injection.',
        'sev': 'High'
      },
      'referrer-policy': {
        'name': 'Referrer Policy',
        'desc': 'Missing Referrer-Policy header may leak sensitive URL parameters in HTTP Referer.',
        'sev': 'Low'
      },
      'permissions-policy': {
        'name': 'Permissions Policy',
        'desc': 'Missing Permissions-Policy allows browser features (camera, microphone, geolocation) by default.',
        'sev': 'Low'
      },
    };

    for (final entry in requiredHeaders.entries) {
      if (!headers.containsKey(entry.key)) {
        findings.add(AbsoluteFinding(
          type: 'Missing Security Header',
          detail: '${entry.value['name']}: ${entry.value['desc']}',
          severity: entry.value['sev']!,
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
      ));

      if (server.contains('Apache/2.2') || server.contains('PHP/5.') || server.contains('IIS/6.0') || server.contains('OpenSSL/0.9')) {
        findings.add(AbsoluteFinding(
          type: 'Outdated Server Technology',
          detail: 'Potentially vulnerable and end-of-life component detected: "$server".',
          severity: 'Critical',
        ));
      }
    }

    if (headers.containsKey('x-powered-by')) {
      findings.add(AbsoluteFinding(
        type: 'Technology Disclosure',
        detail: 'X-Powered-By reveals backend stack: "${headers['x-powered-by']}".',
        severity: 'Low',
      ));
    }

    if (headers.containsKey('x-aspnet-version')) {
      findings.add(AbsoluteFinding(
        type: 'ASP.NET Version Disclosure',
        detail: 'X-AspNet-Version reveals exact framework version: "${headers['x-aspnet-version']}".',
        severity: 'Medium',
      ));
    }
  }

  void _auditCookies(Map<String, String> headers, List<AbsoluteFinding> findings) {
    if (headers.containsKey('set-cookie')) {
      final cookie = headers['set-cookie']!;
      if (!cookie.toLowerCase().contains('httponly')) {
        findings.add(AbsoluteFinding(
          type: 'Insecure Cookie (Missing HttpOnly)',
          detail: 'Session cookie does not have HttpOnly flag set. Vulnerable to XSS token theft.',
          severity: 'High',
        ));
      }
      if (!cookie.toLowerCase().contains('secure')) {
        findings.add(AbsoluteFinding(
          type: 'Insecure Cookie (Missing Secure)',
          detail: 'Cookie transmitted over unencrypted connections (missing Secure flag).',
          severity: 'Medium',
        ));
      }
      if (!cookie.toLowerCase().contains('samesite')) {
        findings.add(AbsoluteFinding(
          type: 'Insecure Cookie (Missing SameSite)',
          detail: 'Cookie missing SameSite attribute (Lax/Strict), increasing CSRF vulnerability risk.',
          severity: 'Low',
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
          detail: 'Access-Control-Allow-Origin is set to wildcard (*), allowing any third-party domain access.',
          severity: 'Medium',
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
          ));
        }
        if (allow.contains('PUT') || allow.contains('DELETE')) {
          findings.add(AbsoluteFinding(
            type: 'Potentially Insecure HTTP Methods',
            detail: 'Server advertises PUT/DELETE capabilities: "$allow".',
            severity: 'Low',
          ));
        }
      }
    } catch (_) {}
  }

  Future<void> _probeSensitivePaths(
    http.Client client,
    String baseUrl,
    List<AbsoluteFinding> findings,
    int concurrency,
    int timeout,
  ) async {
    for (int i = 0; i < sensitivePaths.length; i += concurrency) {
      final chunk = sensitivePaths.skip(i).take(concurrency).toList();
      final futures = chunk.map((item) async {
        final path = item['path']!;
        final url = '$baseUrl$path';
        try {
          final res = await client.get(
            Uri.parse(url),
            headers: {'User-Agent': 'Nikto/2.5.0 (RedOps Hub Local Security Auditor)'},
          ).timeout(Duration(seconds: timeout));

          if (res.statusCode == 200 && res.body.isNotEmpty && !res.body.toLowerCase().contains('404 not found')) {
            return AbsoluteFinding(
              type: 'Exposed Sensitive Resource',
              detail: '/$path -> ${item['desc']} (HTTP 200, Size: ${res.body.length} bytes)',
              severity: item['severity']!,
            );
          }
        } catch (_) {}
        return null;
      }).toList();

      final results = await Future.wait(futures);
      for (final r in results) {
        if (r != null) findings.add(r);
      }
    }
  }
}

class AbsoluteFinding {
  final String type;
  final String detail;
  final String severity;

  AbsoluteFinding({
    required this.type,
    required this.detail,
    required this.severity,
  });

  Map<String, dynamic> toJson() => {
    'type': type,
    'detail': detail,
    'severity': severity,
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
}
