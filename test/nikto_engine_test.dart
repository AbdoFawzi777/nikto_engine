import 'package:flutter_test/flutter_test.dart';
import 'package:nikto_engine/nikto_engine.dart';

void main() {
  test('NiktoEngine initialization test', () async {
    final engine = NiktoEngine();
    await engine.initialize();
    expect(engine.isInitialized, true);
  });
}
