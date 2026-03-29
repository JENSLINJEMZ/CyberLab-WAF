<?php
declare(strict_types=1);

require __DIR__ . '/../../lib/vendor/autoload.php';

use Detection\MobileDetect;

class DeviceIntelligence
{
    private MobileDetect $detect;
    private float $startTime;
    private array $report = [];

    public function __construct()
    {
        $this->startTime = microtime(true);
        $this->detect    = new MobileDetect();
    }

    public function analyze(): array{
        $this->report = [
            'status_code'  => 200,
            'is_success'   => true,
            'failed_reason'=> 'Analysis pending',   // ← placeholder until applyRiskStatus() runs
            'device'       => $this->getDeviceInfo(),
            'os'           => $this->getOSInfo(),
            'browser'      => $this->getBrowserInfo(),
            'network'      => $this->getNetworkInfo(),
            'security'     => $this->getSecurityFlags(),
            'geolocation'  => $this->getGeoInfo(),
            'client_hints' => $this->getClientHints(),
            'request'      => $this->getRequestInfo(),
            'segment'      => $this->classifySegment(),
            'risk_score'   => $this->calculateRiskScore(),
            'meta'         => $this->getMeta(),
        ];

        // Override status if high risk
        $this->applyRiskStatus();

        $this->log();

        return $this->report;
    }

    // ── STATUS ──────────────────────────────────────────────────────────────

    private function applyRiskStatus(): void{
        $risk    = $this->report['risk_score'];
        $sec     = $this->report['security'];
        $net     = $this->report['network'];
        $browser = $this->report['browser'];
        $device  = $this->report['device'];
        $os      = $this->report['os'];
        $geo     = $this->report['geolocation'];
        $hints   = $this->report['client_hints'];
        $request = $this->report['request'];
        $reasons = [];

        // ── LAYER 1: AUTOMATED AGENT DETECTION (Instant Block) ──────────────────
        if ($sec['is_bot'])
            $reasons[] = '[BOT] Automated bot signature found in user agent string';

        if ($sec['is_headless'])
            $reasons[] = '[HEADLESS] Headless browser environment detected (e.g. Puppeteer, Playwright, PhantomJS)';

        if ($sec['is_crawler'])
            $reasons[] = '[CRAWLER] Web crawler or scraper tool identified (e.g. curl, wget, python-requests)';

        // ── LAYER 2: USER AGENT INTEGRITY ───────────────────────────────────────
        if ($sec['ua_mismatch'])
            $reasons[] = '[UA_MISMATCH] User agent claims do not match Sec-CH-UA client hint headers';

        if ($sec['suspicious_ua'])
            $reasons[] = '[SUSPICIOUS_UA] User agent is malformed, too short, or contains injection patterns';

        if ($browser['name'] === 'Unknown')
            $reasons[] = '[UNKNOWN_BROWSER] Could not identify any known browser from the user agent';

        if (empty($device['user_agent']))
            $reasons[] = '[MISSING_UA] No user agent string was provided in the request';

        // ── LAYER 3: NETWORK & IP INTEGRITY ─────────────────────────────────────
        if ($net['is_private_ip'])
            $reasons[] = '[PRIVATE_IP] Request originated from a private or reserved IP address: ' . $net['ip'];

        if ($net['proxy']['detected'])
            $reasons[] = '[PROXY] Request is being routed through a proxy — headers: ' . implode(', ', $net['proxy']['headers']);

        if (!$net['https'])
            $reasons[] = '[INSECURE] Request was made over an unencrypted HTTP connection, not HTTPS';

        if ($net['ip'] === '0.0.0.0')
            $reasons[] = '[INVALID_IP] Could not resolve a valid client IP address from the request';

        // ── LAYER 4: CLIENT HINTS INTEGRITY ─────────────────────────────────────
        if (empty($hints['platform']))
            $reasons[] = '[MISSING_PLATFORM] Sec-CH-UA-Platform client hint is absent';

        if (empty($hints['ua_brands']))
            $reasons[] = '[MISSING_UA_BRANDS] Sec-CH-UA brand list client hint is absent';

        if (!empty($hints['mobile']) && $hints['mobile'] !== ($device['is_mobile'] ? '?1' : '?0'))
            $reasons[] = '[HINT_MOBILE_MISMATCH] Sec-CH-UA-Mobile hint conflicts with detected device type';

        if (!empty($hints['platform']) && !empty($os['name'])
            && stripos($hints['platform'], $os['name']) === false
            && $os['name'] !== 'Unknown')
            $reasons[] = '[HINT_OS_MISMATCH] Sec-CH-UA-Platform "' . $hints['platform'] . '" does not match detected OS "' . $os['name'] . '"';

        // ── LAYER 5: REQUEST INTEGRITY ───────────────────────────────────────────
        if (empty($browser['accept_language']))
            $reasons[] = '[MISSING_LANG] Accept-Language header is missing — uncommon in real browsers';

        if (empty($browser['accept_encoding']))
            $reasons[] = '[MISSING_ENCODING] Accept-Encoding header is missing — uncommon in real browsers';

        if (!$sec['csrf_token_present'] && in_array($request['method'], ['POST', 'PUT', 'PATCH', 'DELETE']))
            $reasons[] = '[MISSING_CSRF] CSRF token header is absent on a state-mutating ' . $request['method'] . ' request';

        if (!empty($request['content_type'])
            && stripos($request['content_type'], 'application/json') === false
            && stripos($request['content_type'], 'multipart') === false
            && stripos($request['content_type'], 'application/x-www-form-urlencoded') === false
            && in_array($request['method'], ['POST', 'PUT', 'PATCH']))
            $reasons[] = '[INVALID_CONTENT_TYPE] Unexpected Content-Type "' . $request['content_type'] . '" for a ' . $request['method'] . ' request';

        // ── LAYER 6: GEO / ORIGIN INTEGRITY ─────────────────────────────────────
        if (empty($geo['country']))
            $reasons[] = '[MISSING_GEO] Could not determine the request origin country';

        if (!empty($sec['origin']) && !empty($request['host'])
            && parse_url($sec['origin'], PHP_URL_HOST) !== $request['host'])
            $reasons[] = '[ORIGIN_MISMATCH] Origin header "' . $sec['origin'] . '" does not match server host "' . $request['host'] . '"';

        // ── LAYER 7: DEVICE CONSISTENCY ──────────────────────────────────────────
        if ($device['type'] === 'Desktop' && $device['brand'] !== 'Unknown')
            $reasons[] = '[DEVICE_CONFLICT] Desktop device type reported but a mobile brand "' . $device['brand'] . '" was detected';

        if ($os['name'] === 'iOS' && $device['type'] === 'Desktop')
            $reasons[] = '[OS_DEVICE_CONFLICT] iOS operating system detected on a non-mobile device type';

        if ($os['name'] === 'Android' && $device['type'] === 'Desktop')
            $reasons[] = '[OS_DEVICE_CONFLICT] Android operating system detected on a non-mobile device type';

        // ── LAYER 8: DO-NOT-TRACK & PRIVACY FLAGS ────────────────────────────────
        if ($browser['do_not_track'] && !empty($sec['referrer']))
            $reasons[] = '[DNT_REFERRER_CONFLICT] Do-Not-Track is enabled but a referrer header is still being sent';

        // ── APPLY FINAL STATUS ───────────────────────────────────────────────────
        if (!empty($reasons)) {
            // Hard block — one or more critical violations detected
            $this->report['status_code']   = 403;
            $this->report['is_success']    = false;
            $this->report['failed_reason'] = implode(' | ', $reasons);

        } elseif ($risk['level'] === 'HIGH') {
            // High risk score — request rejected but not a hard block
            $this->report['status_code']   = 422;
            $this->report['is_success']    = false;
            $this->report['failed_reason'] = 'High risk score (' . $risk['score'] . '/100) — flags: ' . implode(', ', $risk['flags']);

        } elseif ($risk['level'] === 'MEDIUM') {
            // Medium risk — allowed but flagged for review
            $this->report['status_code']   = 200;
            $this->report['is_success']    = true;
            $this->report['failed_reason'] = 'Flagged for review — medium risk score (' . $risk['score'] . '/100): ' . implode(', ', $risk['flags']);

        } else {
            // All clear — low risk, no violations
            $this->report['status_code']   = 200;
            $this->report['is_success']    = true;
            $this->report['failed_reason'] = 'No issues detected — risk score ' . $risk['score'] . '/100 (LOW)';
        }
    }

    // ── DEVICE ──────────────────────────────────────────────────────────────

    private function getDeviceInfo(): array
    {
        $brands = [
            'Apple'    => ['iPhone', 'iPad', 'iPod'],
            'Samsung'  => ['Samsung'],
            'Google'   => ['Pixel', 'Nexus'],
            'Huawei'   => ['Huawei'],
            'OnePlus'  => ['OnePlus'],
            'Xiaomi'   => ['Xiaomi', 'Redmi'],
            'Sony'     => ['Sony'],
            'LG'       => ['LG'],
            'Motorola' => ['Motorola'],
        ];

        $detectedBrand = 'Unknown';
        $detectedModel = 'Unknown';

        foreach ($brands as $brand => $models) {
            foreach ($models as $model) {
                if ($this->detect->is($model)) {
                    $detectedBrand = $brand;
                    $detectedModel = $model;
                    break 2;
                }
            }
        }

        return [
            'type'          => $this->getDeviceType(),
            'brand'         => $detectedBrand,
            'model'         => $detectedModel,
            'is_mobile'     => $this->detect->isMobile(),
            'is_tablet'     => $this->detect->isTablet(),
            'touch_capable' => $this->detect->isMobile() || $this->detect->isTablet(),
            'user_agent'    => $this->detect->getUserAgent(),
        ];
    }

    private function getDeviceType(): string
    {
        if ($this->detect->isTablet()) return 'Tablet';
        if ($this->detect->isMobile()) return 'Mobile';
        return 'Desktop';
    }

    // ── OS ──────────────────────────────────────────────────────────────────

    private function getOSInfo(): array
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $osMap = [
            'iOS'      => fn() => $this->detect->isiOS(),
            'Android'  => fn() => $this->detect->isAndroidOS(),
            'ChromeOS' => fn() => stripos($ua, 'CrOS') !== false,
            'Windows'  => fn() => stripos($ua, 'Windows') !== false,
            'macOS'    => fn() => stripos($ua, 'Macintosh') !== false,
            'Linux'    => fn() => stripos($ua, 'Linux') !== false,
        ];

        $detectedOS = 'Unknown';
        foreach ($osMap as $os => $check) {
            if ($check()) { $detectedOS = $os; break; }
        }

        return [
            'name'    => $detectedOS,
            'version' => $this->extractOSVersion($detectedOS),
            'arch'    => stripos($ua, 'x64') !== false ? 'x64' : 'Unknown',
        ];
    }

    private function extractOSVersion(string $os): ?string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $patterns = [
            'Android' => '/Android\s([\d.]+)/',
            'iOS'     => '/OS\s([\d_]+)\s/',
            'Windows' => '/Windows NT\s([\d.]+)/',
            'macOS'   => '/Mac OS X\s([\d_]+)/',
        ];
        if (isset($patterns[$os]) && preg_match($patterns[$os], $ua, $m)) {
            return str_replace('_', '.', $m[1]);
        }
        return null;
    }

    // ── BROWSER ─────────────────────────────────────────────────────────────

    private function getBrowserInfo(): array
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $browsers = [
            'Edge'            => '/Edg\/([\d.]+)/',
            'Chrome'          => '/Chrome\/([\d.]+)/',
            'Firefox'         => '/Firefox\/([\d.]+)/',
            'Safari'          => '/Version\/([\d.]+).*Safari/',
            'Opera'           => '/OPR\/([\d.]+)/',
            'Samsung Browser' => '/SamsungBrowser\/([\d.]+)/',
            'UC Browser'      => '/UCBrowser\/([\d.]+)/',
        ];

        $name    = 'Unknown';
        $version = null;

        foreach ($browsers as $browser => $pattern) {
            if (preg_match($pattern, $ua, $m)) {
                $name    = $browser;
                $version = $m[1];
                break;
            }
        }

        return [
            'name'            => $name,
            'version'         => $version,
            'engine'          => $this->detectRenderingEngine($ua),
            'do_not_track'    => ($_SERVER['HTTP_DNT'] ?? null) === '1',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
            'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? null,
        ];
    }

    private function detectRenderingEngine(string $ua): string
    {
        if (stripos($ua, 'Gecko') !== false && stripos($ua, 'like Gecko') === false) return 'Gecko';
        if (stripos($ua, 'WebKit') !== false) return 'WebKit/Blink';
        if (stripos($ua, 'Trident') !== false) return 'Trident';
        return 'Unknown';
    }

    // ── NETWORK ─────────────────────────────────────────────────────────────

    private function getNetworkInfo(): array
    {
        $ip = $this->resolveClientIP();

        return [
            'ip'            => $ip,
            'ip_version'    => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'IPv6' : 'IPv4',
            'is_private_ip' => $this->isPrivateIP($ip),
            'proxy'         => $this->detectProxy(),
            'cdn'           => $this->detectCDN(),
            'https'         => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
            'protocol'      => $_SERVER['SERVER_PROTOCOL'] ?? null,
            'port'          => $_SERVER['SERVER_PORT'] ?? null,
            'http2'         => ($_SERVER['SERVER_PROTOCOL'] ?? '') === 'HTTP/2.0',
        ];
    }

    private function resolveClientIP(): string
    {
        $candidates = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR',
        ];

        foreach ($candidates as $key) {
            $val = $_SERVER[$key] ?? null;
            if ($val) {
                $ip = trim(explode(',', $val)[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
            }
        }

        return '0.0.0.0';
    }

    private function isPrivateIP(string $ip): bool
    {
        return !filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    private function detectProxy(): array
    {
        $proxyHeaders = [
            'HTTP_VIA', 'HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED',
            'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP',
        ];

        $found = [];
        foreach ($proxyHeaders as $h) {
            if (!empty($_SERVER[$h])) $found[] = $h;
        }

        return [
            'detected' => !empty($found),
            'headers'  => $found,
        ];
    }

    private function detectCDN(): ?string
    {
        if (!empty($_SERVER['HTTP_CF_RAY']))              return 'Cloudflare';
        if (!empty($_SERVER['HTTP_X_AKAMAI_EDGESCAPE']))  return 'Akamai';
        if (!empty($_SERVER['HTTP_X_AMZ_CF_ID']))         return 'AWS CloudFront';
        if (!empty($_SERVER['HTTP_X_FASTLY_REQUEST_ID'])) return 'Fastly';
        if (!empty($_SERVER['HTTP_X_SUCURI_ID']))         return 'Sucuri';
        return null;
    }

    // ── SECURITY ────────────────────────────────────────────────────────────

    private function getSecurityFlags(): array
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        return [
            'is_bot'             => $this->isBot($ua),
            'is_headless'        => $this->isHeadlessBrowser($ua),
            'is_crawler'         => $this->isCrawler($ua),
            'ua_mismatch'        => $this->detectUAMismatch(),
            'suspicious_ua'      => $this->isSuspiciousUA($ua),
            'referrer'           => $_SERVER['HTTP_REFERER'] ?? null,
            'origin'             => $_SERVER['HTTP_ORIGIN'] ?? null,
            'csrf_token_present' => !empty($_SERVER['HTTP_X_CSRF_TOKEN']),
        ];
    }

    private function isBot(string $ua): bool
    {
        $bots = ['bot', 'crawl', 'spider', 'slurp', 'mediapartners',
                 'Googlebot', 'bingbot', 'YandexBot', 'DuckDuckBot'];
        foreach ($bots as $b) {
            if (stripos($ua, $b) !== false) return true;
        }
        return false;
    }

    private function isHeadlessBrowser(string $ua): bool
    {
        $headless = ['HeadlessChrome', 'PhantomJS', 'Selenium',
                     'WebDriver', 'puppeteer', 'Playwright'];
        foreach ($headless as $h) {
            if (stripos($ua, $h) !== false) return true;
        }
        return false;
    }

    private function isCrawler(string $ua): bool
    {
        return (bool) preg_match('/(crawler|scraper|wget|curl|python-requests|go-http)/i', $ua);
    }

    private function detectUAMismatch(): bool
    {
        if (!isset($_SERVER['HTTP_SEC_CH_UA_MOBILE'])) return false;
        $uaMobile = $this->detect->isMobile();
        $chMobile = $_SERVER['HTTP_SEC_CH_UA_MOBILE'] === '?1';
        return $uaMobile !== $chMobile;
    }

    private function isSuspiciousUA(string $ua): bool
    {
        return strlen($ua) < 20
            || (bool) preg_match('/(eval|base64|<script)/i', $ua);
    }

    // ── GEO ─────────────────────────────────────────────────────────────────

    private function getGeoInfo(): array
    {
        return [
            'country'   => $_SERVER['HTTP_CF_IPCOUNTRY'] ?? $_SERVER['HTTP_X_COUNTRY_CODE'] ?? null,
            'region'    => $_SERVER['HTTP_CF_REGION'] ?? null,
            'city'      => $_SERVER['HTTP_CF_IPCITY'] ?? null,
            'timezone'  => $_SERVER['HTTP_CF_TIMEZONE'] ?? null,
            'latitude'  => $_SERVER['HTTP_CF_IPLATITUDE'] ?? null,
            'longitude' => $_SERVER['HTTP_CF_IPLONGITUDE'] ?? null,
        ];
    }

    // ── CLIENT HINTS ────────────────────────────────────────────────────────

    private function getClientHints(): array
    {
        return [
            'ua_brands'        => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
            'mobile'           => $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? null,
            'platform'         => $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? null,
            'platform_version' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM_VERSION'] ?? null,
            'architecture'     => $_SERVER['HTTP_SEC_CH_UA_ARCH'] ?? null,
            'model'            => $_SERVER['HTTP_SEC_CH_UA_MODEL'] ?? null,
            'bitness'          => $_SERVER['HTTP_SEC_CH_UA_BITNESS'] ?? null,
            'full_version'     => $_SERVER['HTTP_SEC_CH_UA_FULL_VERSION'] ?? null,
        ];
    }

    // ── REQUEST ─────────────────────────────────────────────────────────────

    private function getRequestInfo(): array
    {
        return [
            'method'       => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'uri'          => $_SERVER['REQUEST_URI'] ?? '/',
            'host'         => $_SERVER['HTTP_HOST'] ?? null,
            'content_type' => $_SERVER['CONTENT_TYPE'] ?? null,
            'timestamp'    => date('Y-m-d H:i:s T'),
            'unix_time'    => time(),
        ];
    }

    // ── SEGMENTATION ────────────────────────────────────────────────────────

    private function classifySegment(): string
    {
        $ua    = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $isMob = $this->detect->isMobile();
        $isTab = $this->detect->isTablet();
        $isAnd = $this->detect->isAndroidOS();
        $isiOS = $this->detect->isiOS();

        return match (true) {
            $this->isBot($ua)             => 'Bot/Crawler',
            $this->isHeadlessBrowser($ua) => 'Headless Browser',
            $isMob && $isAnd              => 'Android Mobile',
            $isMob && $isiOS              => 'iOS Mobile',
            $isTab && $isAnd              => 'Android Tablet',
            $isTab && $isiOS              => 'iPad',
            !$isMob && !$isTab            => 'Desktop',
            default                       => 'Unknown',
        };
    }

    // ── RISK SCORE ──────────────────────────────────────────────────────────

    private function calculateRiskScore(): array
    {
        $score = 0;
        $flags = [];
        $ua    = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $checks = [
            [$this->isBot($ua),                          40, 'Bot UA'],
            [$this->isHeadlessBrowser($ua),              35, 'Headless Browser'],
            [$this->isCrawler($ua),                      20, 'Crawler'],
            [$this->detectUAMismatch(),                  25, 'UA/CH Mismatch'],
            [$this->isSuspiciousUA($ua),                 30, 'Suspicious UA'],
            [$this->detectProxy()['detected'],           15, 'Proxy Detected'],
            [$this->isPrivateIP($this->resolveClientIP()), 5, 'Private IP'],
        ];

        foreach ($checks as [$condition, $weight, $label]) {
            if ($condition) { $score += $weight; $flags[] = $label; }
        }

        $score = min($score, 100);

        return [
            'score' => $score,
            'level' => match (true) {
                $score >= 60 => 'HIGH',
                $score >= 30 => 'MEDIUM',
                default      => 'LOW',
            },
            'flags' => $flags,
        ];
    }

    // ── META ────────────────────────────────────────────────────────────────

    private function getMeta(): array
    {
        return [
            'analysis_ms'    => round((microtime(true) - $this->startTime) * 1000, 3),
            'memory_kb'      => round(memory_get_usage() / 1024, 2),
            'peak_memory_kb' => round(memory_get_peak_usage() / 1024, 2),
            'php_version'    => PHP_VERSION,
        ];
    }

    // ── LOGGING ─────────────────────────────────────────────────────────────

    private function log(): void
    {
        $logFile = sys_get_temp_dir() . '/device_intelligence.log';
        $entry   = date('[Y-m-d H:i:s]') . ' ' . json_encode([
            'ip'           => $this->report['network']['ip'] ?? '?',
            'segment'      => $this->report['segment'],
            'risk'         => $this->report['risk_score']['level'],
            'status_code'  => $this->report['status_code'],
            'is_success'   => $this->report['is_success'],
            'failed_reason'=> $this->report['failed_reason'],
            'ms'           => $this->report['meta']['analysis_ms'],
        ]) . PHP_EOL;

        file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
    }
}