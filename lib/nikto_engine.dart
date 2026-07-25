/// 🛡️ Nikto Engine - Web vulnerability scanner for Flutter
library nikto_engine;

import 'package:http/http.dart' as http;

class NiktoEngine {
  static final NiktoEngine _instance = NiktoEngine._internal();
  factory NiktoEngine() => _instance;
  NiktoEngine._internal();

  bool _initialized = false;

  static const List<String> _securityHeaders = [
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'content-security-policy',
    'x-xss-protection',
    'referrer-policy',
    'permissions-policy',
  ];

  static const List<String> _dangerousPaths = [
    '/admin', '/login', '/wp-admin', '/phpmyadmin', '/cpanel',
    '/backup', '/config', '/.git', '/.env', '/robots.txt',
  ];

  /// 🚀 تهيئة المحرك
  Future<void> initialize() async {
    _initialized = true;
  }

  /// 🔍 فحص ثغرات الويب
  Future<NiktoResult> scan(String url) async {
    final issues = <String>[];
    final findings = <Finding>[];

    try {
      final response = await http.get(Uri.parse(url));
      final headers = response.headers;

      // 1. فحص الرؤوس الأمنية
      for (final header in _securityHeaders) {
        if (!headers.containsKey(header)) {
          issues.add('⚠️ Missing Security Header: $header');
          findings.add(Finding(
            type: 'Missing Security Header',
            detail: header,
            severity: 'Medium',
          ));
        }
      }

      // 2. فحص معلومات الخادم
      if (headers.containsKey('server')) {
        final server = headers['server']!;
        issues.add('ℹ️ Server Info: $server');
        findings.add(Finding(
          type: 'Server Information Disclosure',
          detail: server,
          severity: 'Low',
        ));
        
        if (server.contains('Apache/2.2') || server.contains('nginx/1.')) {
          issues.add('⚠️ Outdated Server Version Detected');
          findings.add(Finding(
            type: 'Outdated Server Version',
            detail: server,
            severity: 'High',
          ));
        }
      }

      // 3. فحص الـ Cookies
      if (headers.containsKey('set-cookie')) {
        final cookie = headers['set-cookie']!;
        if (!cookie.contains('Secure')) {
          issues.add('⚠️ Cookie Missing Secure Flag');
          findings.add(Finding(
            type: 'Insecure Cookie',
            detail: 'Secure flag missing',
            severity: 'Medium',
          ));
        }
        if (!cookie.contains('HttpOnly')) {
          issues.add('⚠️ Cookie Missing HttpOnly Flag');
          findings.add(Finding(
            type: 'Insecure Cookie',
            detail: 'HttpOnly flag missing',
            severity: 'Medium',
          ));
        }
      }

      // 4. فحص طريقة HTTPS
      if (url.startsWith('http://')) {
        issues.add('HTTP Instead of HTTPS');
        findings.add(Finding(
          type: 'Mixed Content',
          detail: 'HTTP instead of HTTPS',
          severity: 'High',
        ));
      }

      // 5. فحص المسارات الخطيرة
      for (final path in _dangerousPaths) {
        try {
          final testUrl = '$url$path';
          final testResponse = await http.get(Uri.parse(testUrl));
          if (testResponse.statusCode == 200) {
            issues.add('Dangerous Path Exposed: $path');
            findings.add(Finding(
              type: 'Exposed Dangerous Path',
              detail: path,
              severity: 'Critical',
            ));
          }
        } catch (_) {}
      }

    } catch (e) {
      issues.add('Scan Error: $e');
      findings.add(Finding(
        type: 'Scan Error',
        detail: e.toString(),
        severity: 'Info',
      ));
    }

    return NiktoResult(
      url: url,
      issues: issues,
      findings: findings,
      totalIssues: issues.length,
      totalFindings: findings.length,
    );
  }

  bool get isInitialized => _initialized;
}

class Finding {
  final String type;
  final String detail;
  final String severity;
  Finding({
    required this.type,
    required this.detail,
    required this.severity,
  });
}

class NiktoResult {
  final String url;
  final List<String> issues;
  final List<Finding> findings;
  final int totalIssues;
  final int totalFindings;
  NiktoResult({
    required this.url,
    required this.issues,
    required this.findings,
    required this.totalIssues,
    required this.totalFindings,
  });
}
