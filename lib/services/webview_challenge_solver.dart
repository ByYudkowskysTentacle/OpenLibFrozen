// DDoS-challenge solver.
//
// Anna's Archive sits behind DDoS-Guard. Its clearance cookies (__ddg2_,
// __ddg5_, __ddgid_, __ddgmark_) are HttpOnly, so `document.cookie` can never
// see them - that is what defeated earlier attempts to replay them from Dio.
//
// flutter_inappwebview reads cookies through the native WebView2 cookie store
// rather than through JavaScript, so HttpOnly cookies ARE reachable. That lets
// us solve the challenge in a *headless* webview - no window appears at all -
// and hand the clearance cookies to DDoSProtectionHandler. From then on
// AnnasArchieve._makeRequest replays them on ordinary Dio requests, so the
// webview is not needed again until they expire.
//
// flutter_inappwebview has no Linux implementation, so Linux keeps the older
// visible desktop_webview_window path.

// Dart imports:
import 'dart:async';
import 'dart:convert';
import 'dart:io' as io;

// Package imports:
import 'package:desktop_webview_window/desktop_webview_window.dart'
    as desktop_webview;
import 'package:flutter_inappwebview/flutter_inappwebview.dart' as iaw;

// Project imports:
import 'package:openlib/services/ddos_protection_handler.dart';
import 'package:openlib/services/logger.dart';
import 'package:openlib/services/platform_utils.dart';

class WebviewChallengeSolver {
  WebviewChallengeSolver._();

  static const String _tag = 'ChallengeSolver';

  static final AppLogger _logger = AppLogger();
  static final DDoSProtectionHandler _ddosHandler = DDoSProtectionHandler();

  /// Cookies that must not be replayed from Dio. Cloudflare binds cf_clearance
  /// to the browser's TLS fingerprint, so resending it from an HTTP client gets
  /// the request blocked rather than cleared.
  static const Set<String> _nonReplayableCookies = {'cf_clearance'};

  /// A headless solve needs no human input, so it should fail fast and let the
  /// UI offer manual verification instead of hanging the search.
  static const Duration _headlessTimeout = Duration(seconds: 45);

  /// The visible window may be waiting on a human to work a CAPTCHA.
  static const Duration _visibleTimeout = Duration(minutes: 3);

  /// Windows solves invisibly via flutter_inappwebview; Linux still needs the
  /// separate desktop_webview_window.
  static bool get _isHeadlessSupported => PlatformUtils.isWindows;

  /// Solver only works where some kind of webview is available.
  static bool get isSupported =>
      _isHeadlessSupported || PlatformUtils.isLinux;

  /// Returns true when the given page looks like an unfinished DDoS protection
  /// challenge (DDoS-Guard or Cloudflare) instead of real content.
  static bool isChallengePage({
    required String title,
    required String bodySnippet,
  }) {
    final t = title.toLowerCase();
    final b = bodySnippet.toLowerCase();
    const titleMarkers = [
      'ddos-guard',
      'just a moment',
      'attention required',
      'checking your browser',
      'please wait',
    ];
    const bodyMarkers = [
      'ddos-guard/js-challenge',
      'check.ddos-guard.net',
      'ddg-l10n-title',
      'cf-turnstile',
      'challenge-platform',
      'cf-browser-verification',
    ];
    return titleMarkers.any(t.contains) || bodyMarkers.any(b.contains);
  }

  /// Passes the DDoS-Guard / Cloudflare check at [url] and returns the rendered
  /// page HTML.
  ///
  /// On Windows this happens headlessly, with no window shown, and the
  /// resulting clearance cookies are stored so later requests skip the webview
  /// entirely. On Linux a webview window is opened so the user can complete the
  /// check.
  ///
  /// [userAgent] should match the one the HTTP client sends: DDoS-Guard ties its
  /// clearance cookies to the user agent that earned them, so a mismatch makes
  /// the harvested cookies useless.
  ///
  /// Returns null if unsupported, the window was closed early, or the timeout
  /// elapsed without the challenge clearing.
  static Future<String?> fetchHtmlAfterChallenge(
    String url, {
    Duration? timeout,
    String? userAgent,
  }) async {
    if (_isHeadlessSupported) {
      return _solveHeadless(
        url,
        timeout: timeout ?? _headlessTimeout,
        userAgent: userAgent,
      );
    }
    if (PlatformUtils.isLinux) {
      return _solveInVisibleWindow(url, timeout: timeout ?? _visibleTimeout);
    }
    return null;
  }

  // ==================================================================
  // HEADLESS PATH (Windows)
  // ==================================================================

  static Future<String?> _solveHeadless(
    String url, {
    required Duration timeout,
    String? userAgent,
  }) async {
    iaw.HeadlessInAppWebView? headless;
    try {
      headless = iaw.HeadlessInAppWebView(
        initialUrlRequest: iaw.URLRequest(url: iaw.WebUri(url)),
        initialSettings: iaw.InAppWebViewSettings(
          javaScriptEnabled: true,
          // Empty string leaves the platform default in place.
          userAgent: userAgent ?? '',
        ),
      );
      await headless.run();
      _logger.info('Solving challenge headlessly',
          tag: _tag, metadata: {'url': url});

      final deadline = DateTime.now().add(timeout);
      var titleOkPolls = 0;

      while (DateTime.now().isBefore(deadline)) {
        await Future.delayed(const Duration(milliseconds: 1500));

        final controller = headless.webViewController;
        if (controller == null) continue;

        final title = await _eval(controller, 'document.title') ?? '';
        final bodySnippet = await _eval(
              controller,
              "(document.body ? document.body.innerHTML.slice(0, 3000) : '')",
            ) ??
            '';

        if (title.isEmpty && bodySnippet.isEmpty) continue;

        if (isChallengePage(title: title, bodySnippet: bodySnippet)) {
          titleOkPolls = 0;
          _logger.debug('Challenge still active',
              tag: _tag,
              metadata: {'title': title.isEmpty ? '(none)' : title});
          continue;
        }

        // Title is no longer a challenge page, but the document may still be
        // loading/hydrating. Grabbing too early yields an empty body and the
        // parser reports "no results" even though the challenge was solved.
        final readyState = await _eval(controller, 'document.readyState') ?? '';
        if (readyState != 'complete') {
          titleOkPolls++;
          _logger.debug('Page rendering, waiting for readyState=complete',
              tag: _tag,
              metadata: {'readyState': readyState, 'polls': titleOkPolls});
          // Best-effort fallback: after ~15s of good titles with an incomplete
          // state, grab whatever is there.
          if (titleOkPolls < 10) continue;
        }

        // Small settle delay so late XHR content lands in the DOM.
        await Future.delayed(const Duration(milliseconds: 2000));

        final html = await _eval(controller, 'document.documentElement.outerHTML');
        if (html != null && html.isNotEmpty) {
          _logger.info('Challenge solved headlessly, captured page HTML',
              tag: _tag,
              metadata: {'length': html.length, 'title': title});
          // Harvest before disposing - the cookie store goes away with the view.
          await _storeClearanceCookies(url);
          return html;
        }
      }

      _logger.warning('Headless challenge solver timed out', tag: _tag);
      return null;
    } catch (e, st) {
      _logger.error('Headless challenge solver failed',
          tag: _tag, error: e, stackTrace: st);
      return null;
    } finally {
      try {
        await headless?.dispose();
      } catch (_) {
        // Disposal failures are not worth surfacing; nothing is visible anyway.
      }
    }
  }

  /// Copies the webview's cookies - HttpOnly ones included, which is the whole
  /// point - into DDoSProtectionHandler so AnnasArchieve._makeRequest can
  /// replay them on plain Dio requests.
  static Future<void> _storeClearanceCookies(String url) async {
    try {
      final uri = Uri.parse(url);
      final cookies = await iaw.CookieManager.instance()
          .getCookies(url: iaw.WebUri(uri.origin));

      final replayable = <io.Cookie>[];
      for (final cookie in cookies) {
        if (_nonReplayableCookies.contains(cookie.name)) continue;
        final value = cookie.value?.toString() ?? '';
        if (value.isEmpty) continue;
        try {
          replayable.add(io.Cookie(cookie.name, value));
        } catch (_) {
          // dart:io rejects some characters in cookie values; skip those.
        }
      }

      if (replayable.isEmpty) {
        _logger.warning('No replayable cookies found after solve', tag: _tag);
        return;
      }

      await _ddosHandler.storeCookies(uri.host, replayable);
      _logger.info('Stored clearance cookies from headless webview',
          tag: _tag,
          metadata: {
            'domain': uri.host,
            'count': replayable.length,
            'names': replayable.map((c) => c.name).join(','),
          });
    } catch (e) {
      _logger.warning('Failed to harvest cookies from headless webview',
          tag: _tag, error: e.toString());
    }
  }

  static Future<String?> _eval(
      iaw.InAppWebViewController controller, String source) async {
    try {
      final result = await controller.evaluateJavascript(source: source);
      return result?.toString();
    } catch (_) {
      return null;
    }
  }

  // ==================================================================
  // VISIBLE WINDOW PATH (Linux)
  // ==================================================================

  static Future<String?> _solveInVisibleWindow(
    String url, {
    required Duration timeout,
  }) async {
    desktop_webview.Webview? webview;
    var closedByUser = false;
    try {
      webview = await desktop_webview.WebviewWindow.create(
        configuration: const desktop_webview.CreateConfiguration(
          windowHeight: 700,
          windowWidth: 1000,
          title: "Verifying access...",
        ),
      );
      webview.onClose.then((_) => closedByUser = true);
      webview.launch(url);

      final deadline = DateTime.now().add(timeout);
      var titleOkPolls = 0;
      while (DateTime.now().isBefore(deadline)) {
        await Future.delayed(const Duration(milliseconds: 1500));
        if (closedByUser) {
          _logger.info('Challenge webview closed by user', tag: _tag);
          return null;
        }
        final live = webview;
        if (live == null) return null;

        final title = await _js(live, "document.title") ?? '';
        final bodySnippet = await _js(
              live,
              "(document.body ? document.body.innerHTML.slice(0, 3000) : '')",
            ) ??
            '';

        if (title.isEmpty && bodySnippet.isEmpty) continue;

        if (isChallengePage(title: title, bodySnippet: bodySnippet)) {
          titleOkPolls = 0;
          _logger.debug('Challenge still active',
              tag: _tag,
              metadata: {'title': title.isEmpty ? '(none)' : title});
          continue;
        }

        final readyState = await _js(live, "document.readyState") ?? '';
        if (readyState != 'complete') {
          titleOkPolls++;
          _logger.debug('Page rendering, waiting for readyState=complete',
              tag: _tag,
              metadata: {'readyState': readyState, 'polls': titleOkPolls});
          if (titleOkPolls < 10) continue;
        }

        await Future.delayed(const Duration(milliseconds: 2000));

        final html = await _js(live, "document.documentElement.outerHTML");
        if (html != null && html.isNotEmpty) {
          _logger.info('Challenge solved, captured page HTML',
              tag: _tag,
              metadata: {'length': html.length, 'title': title});
          return html;
        }
      }
      _logger.warning('Challenge solver timed out', tag: _tag);
      return null;
    } catch (e, st) {
      _logger.error('Challenge solver failed',
          tag: _tag, error: e, stackTrace: st);
      return null;
    } finally {
      // Don't call close() - causes GTK crashes. Let user close manually or GC clean up.
      webview = null;
    }
  }

  static Future<String?> _js(
      desktop_webview.Webview webview, String script) async {
    try {
      final result = await webview.evaluateJavaScript(script);
      if (result == null) return null;
      var s = result.toString();
      // WebKit (and the plugin's JS bridge) may return strings JSON-encoded.
      if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
        try {
          final decoded = json.decode(s);
          if (decoded is String) return decoded;
        } catch (_) {}
        // Fallback: strip only the outer quote pair.
        return s.substring(1, s.length - 1);
      }
      return s;
    } catch (_) {
      return null;
    }
  }
}
