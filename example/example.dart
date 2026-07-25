import 'package:nikto_engine/nikto_engine.dart';

void main() async {
  final engine = NiktoEngine();
  await engine.initialize();
  print('NiktoEngine is ready for tactical operations.');
}
