// Dart imports:
import 'dart:async';

// Flutter imports:
import 'package:flutter/material.dart';

// Package imports:
import 'package:local_session_timeout/local_session_timeout.dart';

// Project imports:
import 'package:safenotes/data/preference_and_config.dart';
import 'package:safenotes/views/authentication/login.dart';
import 'package:safenotes/views/authentication/set_passphrase.dart';

class AuthWall extends StatelessWidget {
  final StreamController<SessionState> sessionStateStream;
  final bool? isKeyboardFocused;

  AuthWall({Key? key, required this.sessionStateStream, this.isKeyboardFocused})
      : super(key: key);

  @override
  Widget build(BuildContext context) {
    return PreferencesStorage.passPhraseHash.isNotEmpty
        ? EncryptionPhraseLoginPage(
            sessionStream: sessionStateStream,
            isKeyboardFocused: this.isKeyboardFocused,
          )
        : SetEncryptionPhrasePage(
            sessionStream: sessionStateStream,
            isKeyboardFocused: this.isKeyboardFocused,
          );
  }
}
