# Nikto Engine (`nikto_engine`)

> Web Server Misconfiguration & Vulnerability Scanner  
> **Author & Original Architect:** [Abdallah Fawzi Ali Mahmoud](https://github.com/AbdoFawzi777)  
> **Part of the RedOps Hub Monorepo Suite**

---

## 📌 Overview
`nikto_engine` is a production-grade, standalone Flutter package engineered for high-performance mobile security auditing. Built with pure Dart and native Flutter MethodChannels/Isolates, it delivers enterprise-level capability directly on Android & iOS devices without relying on external Linux command-line dependencies.

---

## 🚀 New Capabilities & Features (v2.0)
- **Comprehensive Vulnerability Checks:** Scans for over 6,700 dangerous files, CGIs, and outdated server components.
- **Security Header Inspection:** Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Server tokens.
- **Outdated Software Detection:** Flags vulnerable web server versions (Apache, Nginx, IIS, LiteSpeed).
- **Subdomain & Port Customization:** Full support for non-standard web ports and SSL endpoints.

---

## 🛠 Usage & Integration

Add `nikto_engine` to your Flutter `pubspec.yaml`:

```yaml
dependencies:
  nikto_engine:
    path: ../packages/nikto_engine
```

### Basic Example

```dart
import 'package:nikto_engine/nikto_engine.dart';

void main() async {
  final engine = NiktoEngine();
  
  print('Starting Nikto Engine audit...');
  final results = await engine.execute(
    target: '192.168.1.1',
  );
  
  print('Audit Complete!');
}
```

---

## 🔒 Security & Privacy
- **Zero Telemetry:** No analytics, tracking, or network calls home.
- **Encrypted Local Storage:** Integrates seamlessly with RedOps Hub AES-256 local database.
- **Thread Safety:** All heavy operations execute inside Dart Isolates to maintain 60fps UI rendering.

---

## 👤 Author & Copyright

**Abdallah Fawzi Ali Mahmoud**  
Lead Developer & Security Architect of RedOps Hub  
- **GitHub:** [@AbdoFawzi777](https://github.com/AbdoFawzi777)  
- **Telegram:** [@ABdo_FawZi1](https://telegram.me/ABdo_FawZi1)  
- **Website:** [RedOps Hub Platform](https://redops-hub.web.app)

*Copyright (c) 2026 Abdallah Fawzi Ali Mahmoud. All rights reserved.*
