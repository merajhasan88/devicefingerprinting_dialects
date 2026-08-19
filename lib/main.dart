import 'package:flutter/material.dart';

import 'chatroompage.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const DeviceRecognitionApp());
}

class DeviceRecognitionApp extends StatelessWidget {
  const DeviceRecognitionApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Device Recognition Lab',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const DeviceRecognitionPage(),
    );
  }
}
