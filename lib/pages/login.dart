import 'dart:convert';
import 'dart:math';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/material.dart';
import 'package:flutter_web_auth/flutter_web_auth.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:flutter_facebook_auth/flutter_facebook_auth.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
import 'package:uuid/uuid.dart';

final serverDomain = dotenv.get('SERVER_DOMAIN');
final serverUrl = dotenv.get('SERVER_URL');

final callbackPathSignInAppleForAndroid =
    dotenv.get('CALLBACK_PATH_SIGN_IN_APPLE_FOR_ANDROID');
final callbackPathSignInAppleForIos =
    dotenv.get('CALLBACK_PATH_SIGN_IN_APPLE_FOR_IOS');
final callbackPathSignInKakao = dotenv.get('CALLBACK_PATH_SIGN_IN_KAKAO');
final callbackPathSignInNaver = dotenv.get('CALLBACK_PATH_SIGN_IN_NAVER');

final pathSignInApple = dotenv.get('PATH_SIGN_IN_APPLE');
final pathSignInKakao = dotenv.get('PATH_SIGN_IN_KAKAO');
final pathSignInNaver = dotenv.get('PATH_SIGN_IN_NAVER');

final appleServiceClientId = dotenv.get('APPLE_SERVICE_CLIENT_ID');
final kakaoRestAPIKey = dotenv.get('KAKAO_REST_API_KEY');
final naverClientId = dotenv.get('NAVER_CLIENT_ID');
final naverSecret = dotenv.get('NAVER_SECRET');

class LoginWidget extends StatelessWidget {
  const LoginWidget({Key? key}) : super(key: key);

  /// Generates a cryptographically secure random nonce, to be included in a
  /// credential request.
  String generateNonce([int length = 32]) {
    const charset =
        '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._';
    final random = Random.secure();
    return List.generate(length, (_) => charset[random.nextInt(charset.length)])
        .join();
  }

  /// Returns the sha256 hash of [input] in hex notation.
  String sha256ofString(String input) {
    final bytes = utf8.encode(input);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  Future<UserCredential> signInWithGoogle() async {
    // Trigger the authentication flow
    final GoogleSignInAccount? googleUser = await GoogleSignIn().signIn();

    // Obtain the auth details from the request
    final GoogleSignInAuthentication? googleAuth =
        await googleUser?.authentication;

    // Create a new credential
    final credential = GoogleAuthProvider.credential(
      accessToken: googleAuth?.accessToken,
      idToken: googleAuth?.idToken,
    );

    // Once signed in, return the UserCredential
    return await FirebaseAuth.instance.signInWithCredential(credential);
  }

  // Facebook login
  Future<UserCredential> signInWithFacebook() async {
    // Trigger the sign-in flow
    final LoginResult loginResult = await FacebookAuth.instance.login();

    // Create a credential from the access token
    final OAuthCredential facebookAuthCredential =
        FacebookAuthProvider.credential(loginResult.accessToken!.token);

    // Once signed in, return the UserCredential
    return FirebaseAuth.instance.signInWithCredential(facebookAuthCredential);
  }

  // Apple login
  Future<UserCredential> signInWithApple() async {
    if (await SignInWithApple.isAvailable()) {
      return _signInWithAppleOverIOS13AndAndroid();
    } else {
      return _signInWithAppleUnderIOS13();
    }
  }

  Future<UserCredential> _signInWithAppleOverIOS13AndAndroid() async {
    // To prevent replay attacks with the credential returned from Apple, we
    // include a nonce in the credential request. When signing in with
    // Firebase, the nonce in the id token returned by Apple, is expected to
    // match the sha256 hash of `rawNonce`.
    final rawNonce = generateNonce();
    final nonce = sha256ofString(rawNonce);

    // Request credential for the currently signed in Apple account.
    final appleCredential = await SignInWithApple.getAppleIDCredential(
      scopes: [
        AppleIDAuthorizationScopes.email,
        AppleIDAuthorizationScopes.fullName,
      ],
      nonce: nonce,
      webAuthenticationOptions: WebAuthenticationOptions(
        clientId: appleServiceClientId,
        redirectUri: Uri.https(
          serverDomain,
          callbackPathSignInAppleForAndroid,
        ),
      ),
    );

    // Create an `OAuthCredential` from the credential returned by Apple.
    // iOS 외에는 accessToken으로 code를 꼭 넣어줘야 함.
    final oauthCredential = OAuthProvider("apple.com").credential(
      idToken: appleCredential.identityToken,
      accessToken: appleCredential.authorizationCode,
      rawNonce: rawNonce,
    );

    // Sign in the user with Firebase. If the nonce we generated earlier does
    // not match the nonce in `appleCredential.identityToken`, sign in will fail.
    return await FirebaseAuth.instance.signInWithCredential(oauthCredential);
  }

  Future<UserCredential> _signInWithAppleUnderIOS13() async {
    final url = Uri.https(
      'appleid.apple.com',
      '/auth/authorize',
      {
        'response_type': 'code id_token',
        'client_id': appleServiceClientId,
        'response_mode': 'form_post',
        'redirect_uri': Uri.https(
          serverDomain,
          callbackPathSignInAppleForIos,
        ).toString(),
        'scope': 'email name',
      },
    );

    final result = await FlutterWebAuth.authenticate(
        url: url.toString(), callbackUrlScheme: "applink");

    final body = Uri.parse(result).queryParameters;
    final oauthCredential = OAuthProvider("apple.com").credential(
      idToken: body['id_token'],
      accessToken: body['code'],
    );
    return await FirebaseAuth.instance.signInWithCredential(oauthCredential);
  }

  Future<UserCredential> signInWithKakao() async {
    final state = const Uuid().v4();

    final url = Uri.https(
      'kauth.kakao.com',
      '/oauth/authorize',
      {
        'response_type': 'code',
        'client_id': kakaoRestAPIKey,
        'redirect_uri': serverUrl + callbackPathSignInKakao,
        'state': state,
      },
    );

    final result = await FlutterWebAuth.authenticate(
      url: url.toString(),
      callbackUrlScheme: 'webauthcallback',
    );

    final code = Uri.parse(result).queryParameters['code'];

    final response = await http.post(
      Uri.https('kauth.kakao.com', '/oauth/token'),
      body: {
        'grant_type': 'authorization_code',
        'client_id': kakaoRestAPIKey,
        'redirect_uri': serverUrl + callbackPathSignInKakao,
        'code': code,
        'state': state,
      },
    );

    final accessToken = json.decode(response.body)['access_token'] as String;

    final responseCustomToken = await http.post(
      Uri.parse(serverUrl + pathSignInKakao),
      body: {
        "accessToken": accessToken,
      },
    );

    return await FirebaseAuth.instance
        .signInWithCustomToken(responseCustomToken.body);
  }

  Future<UserCredential> signInWithNaver() async {
    final state = const Uuid().v4();

    final url = Uri.https(
      'nid.naver.com',
      '/oauth2.0/authorize',
      {
        'response_type': 'code',
        'client_id': naverClientId,
        'redirect_uri': serverUrl + callbackPathSignInNaver,
        'state': state,
      },
    );

    final result = await FlutterWebAuth.authenticate(
      url: url.toString(),
      callbackUrlScheme: 'webauthcallback',
    );

    final code = Uri.parse(result).queryParameters['code'];

    final response = await http.post(
      Uri.https('nid.naver.com', '/oauth2.0/token'),
      body: {
        'grant_type': 'authorization_code',
        'client_id': naverClientId,
        'client_secret': naverSecret,
        'code': code,
        'state': state,
      },
    );

    final accessToken = json.decode(response.body)['access_token'] as String;

    final responseCustomToken = await http.post(
      Uri.parse(serverUrl + pathSignInNaver),
      body: {
        "accessToken": accessToken,
      },
    );

    return await FirebaseAuth.instance
        .signInWithCustomToken(responseCustomToken.body);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('SNS Login')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            ElevatedButton(
              onPressed: signInWithGoogle,
              child: const Text('Google Login'),
              style: ButtonStyle(
                backgroundColor: MaterialStateProperty.resolveWith<Color>(
                  (states) => Colors.grey.withOpacity(0.3),
                ),
              ),
            ),
            ElevatedButton(
              onPressed: signInWithFacebook,
              child: const Text('Facebook Login'),
              style: ButtonStyle(
                backgroundColor: MaterialStateProperty.resolveWith<Color>(
                  (states) => Colors.grey.withOpacity(0.3),
                ),
              ),
            ),
            ElevatedButton(
              onPressed: signInWithApple,
              child: const Text('Apple Login'),
              style: ButtonStyle(
                backgroundColor: MaterialStateProperty.resolveWith<Color>(
                  (states) => Colors.grey.withOpacity(0.3),
                ),
              ),
            ),
            ElevatedButton(
              onPressed: signInWithKakao,
              child: const Text('Kakao Login'),
              style: ButtonStyle(
                backgroundColor: MaterialStateProperty.resolveWith<Color>(
                  (states) => Colors.grey.withOpacity(0.3),
                ),
              ),
            ),
            ElevatedButton(
              onPressed: signInWithNaver,
              child: const Text('Naver Login'),
              style: ButtonStyle(
                backgroundColor: MaterialStateProperty.resolveWith<Color>(
                  (states) => Colors.grey.withOpacity(0.3),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
