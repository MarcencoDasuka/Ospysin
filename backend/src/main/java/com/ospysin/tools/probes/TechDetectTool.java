package com.ospysin.tools.probes;

import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Tool #9: Technology Fingerprint Heuristics direct probe (tech_detect).
 * Probes HTTP response headers, cookies, HTML meta generator tags, script URLs,
 * and DOM markers to detect web servers, frameworks, CMS platforms, frontend libraries,
 * and reverse proxies with version extraction and confidence ratings.
 */
@Component
public class TechDetectTool implements OspysinTool {

    public static final String TOOL_ID = "tech_detect";
    public static final long WIRE_CAP_BYTES = 1024 * 1024L; // 1 MB
    public static final long DECOMPRESSED_CAP_BYTES = 5 * 1024 * 1024L; // 5 MB
    public static final int READ_TIMEOUT_MS = 10_000; // 10s

    // Server header patterns
    private static final Pattern NGINX_PATTERN = Pattern.compile("nginx(?:/([0-9.]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern APACHE_PATTERN = Pattern.compile("(?:apache|httpd)(?:/([0-9.]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern IIS_PATTERN = Pattern.compile("microsoft-iis(?:/([0-9.]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern CADDY_PATTERN = Pattern.compile("caddy(?:/v?([0-9.]+))?", Pattern.CASE_INSENSITIVE);

    // Runtime / Framework header patterns
    private static final Pattern PHP_HEADER_PATTERN = Pattern.compile("php(?:/([0-9.]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXPRESS_HEADER_PATTERN = Pattern.compile("express(?:/([0-9.]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern ASPNET_HEADER_PATTERN = Pattern.compile("asp\\.net(?:/([0-9.]+))?", Pattern.CASE_INSENSITIVE);

    // Meta generator patterns
    private static final Pattern WORDPRESS_META_PATTERN = Pattern.compile("wordpress(?:[ /]([0-9.]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern DRUPAL_META_PATTERN = Pattern.compile("drupal(?:[ /]([0-9.]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern JOOMLA_META_PATTERN = Pattern.compile("joomla(?:[ /!?]*([0-9.]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern GHOST_META_PATTERN = Pattern.compile("ghost(?:[ /]([0-9.]+))?", Pattern.CASE_INSENSITIVE);

    // Script / Asset URL patterns
    private static final Pattern JQUERY_URL_PATTERN = Pattern.compile("jquery(?:[.-]([0-9.]+)|/([0-9.]+)/)", Pattern.CASE_INSENSITIVE);
    private static final Pattern VUE_URL_PATTERN = Pattern.compile("vue(?:@|/|-)([0-9.]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ANGULAR_URL_PATTERN = Pattern.compile("(?:angular(?:js)?)[.-/]([0-9.]+)|/([0-9.]+)/angular(?:\\.min)?\\.js", Pattern.CASE_INSENSITIVE);
    private static final Pattern BOOTSTRAP_URL_PATTERN = Pattern.compile("bootstrap(?:/|-)([0-9.]+)", Pattern.CASE_INSENSITIVE);

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;

    @Autowired
    public TechDetectTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine) {
        this.pinnedHttpClient = Objects.requireNonNull(pinnedHttpClient, "pinnedHttpClient must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
    }

    @Override
    public String getToolId() {
        return TOOL_ID;
    }

    @Override
    public void validateParams(Map<String, Object> params) throws ValidationException {
        // Schema requires empty or optional parameters
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        URI initialUri = URI.create(context.targetUrl().trim());

        InetAddress pinnedIp;
        if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
            pinnedIp = context.policyDecision().resolvedIp();
        } else {
            PolicyDecision decision = policyEngine.evaluate(initialUri, context.mode(), context.scopeAsset());
            if (!decision.allowed()) {
                throw new PolicyViolationException(
                        "Policy violation for tech_detect: " + decision.reason(),
                        List.of(new InvalidParam("targetUrl", decision.reason()))
                );
            }
            pinnedIp = decision.resolvedIp();
        }

        PinnedProbeResult probeResult = pinnedHttpClient.executeWithRedirects(
                initialUri,
                pinnedIp,
                true,
                context.mode(),
                context.scopeAsset(),
                WIRE_CAP_BYTES,
                DECOMPRESSED_CAP_BYTES,
                READ_TIMEOUT_MS
        );

        Map<String, DetectedTech> detectedMap = new LinkedHashMap<>();

        // 1. Inspect HTTP Response Headers
        inspectHeaders(probeResult.normalizedHeaders(), detectedMap);

        // 2. Inspect Cookies
        inspectCookies(probeResult.cookies(), detectedMap);

        // 3. Inspect HTML DOM & Body Markers
        String bodyText = probeResult.bodyText();
        inspectBodyAndDom(bodyText, probeResult.finalUrl(), detectedMap);

        // Build sorted/normalized technologies list
        List<Map<String, Object>> technologies = new ArrayList<>();
        List<ObservationDraft> observations = new ArrayList<>();

        for (DetectedTech tech : detectedMap.values()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", tech.name);
            entry.put("version", tech.version);
            entry.put("category", tech.category);
            entry.put("confidence", tech.confidence);
            entry.put("evidence", tech.evidence);
            technologies.add(entry);

            if (tech.version != null && !tech.version.isBlank()) {
                observations.add(new ObservationDraft(
                        "TECH_VERSION_EXPOSED",
                        "Technology version disclosed: " + tech.name + " " + tech.version + " (" + tech.evidence + ")",
                        SeverityHeuristic.LOW
                ));
            }
        }

        if (!technologies.isEmpty()) {
            String summaryNames = technologies.stream()
                    .map(t -> (String) t.get("name"))
                    .distinct()
                    .collect(Collectors.joining(", "));
            observations.add(new ObservationDraft(
                    "TECH_FINGERPRINT",
                    "Fingerprinted " + technologies.size() + " technology component(s): " + summaryNames,
                    SeverityHeuristic.INFO
            ));
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("statusCode", probeResult.finalStatusCode());
        parsedData.put("technologies", technologies);

        // Architectural invariant: score = null for tech_detect
        return new ToolExecutionOutcome(
                probeResult.rawOutput(),
                parsedData,
                null,
                false,
                observations
        );
    }

    private void inspectHeaders(Map<String, Object> headers, Map<String, DetectedTech> detectedMap) {
        if (headers == null || headers.isEmpty()) {
            return;
        }

        // Server header
        if (headers.containsKey("server")) {
            String server = headers.get("server").toString().trim();
            inspectServerHeader(server, detectedMap);
        }

        // X-Powered-By / X-Generator / X-AspNet-Version / Via / X-Varnish
        if (headers.containsKey("x-powered-by")) {
            String poweredBy = headers.get("x-powered-by").toString().trim();
            inspectPoweredBy(poweredBy, detectedMap);
        }

        if (headers.containsKey("x-generator")) {
            String generator = headers.get("x-generator").toString().trim();
            inspectGeneratorHeader(generator, detectedMap);
        }

        if (headers.containsKey("x-aspnet-version")) {
            String aspnetVer = headers.get("x-aspnet-version").toString().trim();
            recordTech(detectedMap, new DetectedTech("ASP.NET", cleanVersion(aspnetVer), "Backend Framework", "CONFIRMED", "Header x-aspnet-version: " + aspnetVer));
        }

        if (headers.containsKey("via")) {
            String via = headers.get("via").toString().trim();
            if (via.toLowerCase(Locale.ROOT).contains("varnish")) {
                recordTech(detectedMap, new DetectedTech("Varnish", null, "Reverse Proxy / CDN", "CONFIRMED", "Header via: " + via));
            }
        }

        if (headers.containsKey("x-varnish")) {
            recordTech(detectedMap, new DetectedTech("Varnish", null, "Reverse Proxy / CDN", "CONFIRMED", "Header x-varnish present"));
        }

        // Spring Boot application context header
        if (headers.containsKey("x-application-context")) {
            recordTech(detectedMap, new DetectedTech("Spring Boot", null, "Backend Framework", "CONFIRMED", "Header x-application-context present"));
        }
    }

    private void inspectServerHeader(String server, Map<String, DetectedTech> detectedMap) {
        String lower = server.toLowerCase(Locale.ROOT);

        // Nginx
        Matcher mNginx = NGINX_PATTERN.matcher(server);
        if (mNginx.find()) {
            String ver = mNginx.group(1);
            recordTech(detectedMap, new DetectedTech("Nginx", cleanVersion(ver), "Web Server", "CONFIRMED", "Header server: " + server));
        } else if (lower.contains("nginx")) {
            recordTech(detectedMap, new DetectedTech("Nginx", null, "Web Server", "CONFIRMED", "Header server: " + server));
        }

        // Apache HTTP Server
        Matcher mApache = APACHE_PATTERN.matcher(server);
        if (mApache.find()) {
            String ver = mApache.group(1);
            recordTech(detectedMap, new DetectedTech("Apache HTTP Server", cleanVersion(ver), "Web Server", "CONFIRMED", "Header server: " + server));
        } else if (lower.contains("apache") || lower.contains("httpd")) {
            recordTech(detectedMap, new DetectedTech("Apache HTTP Server", null, "Web Server", "CONFIRMED", "Header server: " + server));
        }

        // Microsoft IIS
        Matcher mIis = IIS_PATTERN.matcher(server);
        if (mIis.find()) {
            String ver = mIis.group(1);
            recordTech(detectedMap, new DetectedTech("Microsoft IIS", cleanVersion(ver), "Web Server", "CONFIRMED", "Header server: " + server));
        } else if (lower.contains("microsoft-iis")) {
            recordTech(detectedMap, new DetectedTech("Microsoft IIS", null, "Web Server", "CONFIRMED", "Header server: " + server));
        }

        // Caddy
        Matcher mCaddy = CADDY_PATTERN.matcher(server);
        if (mCaddy.find()) {
            String ver = mCaddy.group(1);
            recordTech(detectedMap, new DetectedTech("Caddy", cleanVersion(ver), "Web Server", "CONFIRMED", "Header server: " + server));
        } else if (lower.contains("caddy")) {
            recordTech(detectedMap, new DetectedTech("Caddy", null, "Web Server", "CONFIRMED", "Header server: " + server));
        }

        // Cloudflare
        if (lower.contains("cloudflare")) {
            recordTech(detectedMap, new DetectedTech("Cloudflare", null, "Reverse Proxy / CDN", "CONFIRMED", "Header server: " + server));
        }

        // LiteSpeed
        if (lower.contains("litespeed")) {
            recordTech(detectedMap, new DetectedTech("LiteSpeed", null, "Web Server", "CONFIRMED", "Header server: " + server));
        }

        // Envoy
        if (lower.contains("envoy")) {
            recordTech(detectedMap, new DetectedTech("Envoy", null, "Reverse Proxy / CDN", "CONFIRMED", "Header server: " + server));
        }
    }

    private void inspectPoweredBy(String poweredBy, Map<String, DetectedTech> detectedMap) {
        String lower = poweredBy.toLowerCase(Locale.ROOT);

        // PHP
        Matcher mPhp = PHP_HEADER_PATTERN.matcher(poweredBy);
        if (mPhp.find()) {
            String ver = mPhp.group(1);
            recordTech(detectedMap, new DetectedTech("PHP", cleanVersion(ver), "Backend Runtime", "CONFIRMED", "Header x-powered-by: " + poweredBy));
        } else if (lower.contains("php")) {
            recordTech(detectedMap, new DetectedTech("PHP", null, "Backend Runtime", "CONFIRMED", "Header x-powered-by: " + poweredBy));
        }

        // Express
        Matcher mExpress = EXPRESS_HEADER_PATTERN.matcher(poweredBy);
        if (mExpress.find()) {
            String ver = mExpress.group(1);
            recordTech(detectedMap, new DetectedTech("Express", cleanVersion(ver), "Backend Framework", "CONFIRMED", "Header x-powered-by: " + poweredBy));
        } else if (lower.contains("express")) {
            recordTech(detectedMap, new DetectedTech("Express", null, "Backend Framework", "CONFIRMED", "Header x-powered-by: " + poweredBy));
        }

        // ASP.NET
        Matcher mAspnet = ASPNET_HEADER_PATTERN.matcher(poweredBy);
        if (mAspnet.find()) {
            String ver = mAspnet.group(1);
            recordTech(detectedMap, new DetectedTech("ASP.NET", cleanVersion(ver), "Backend Framework", "CONFIRMED", "Header x-powered-by: " + poweredBy));
        } else if (lower.contains("asp.net")) {
            recordTech(detectedMap, new DetectedTech("ASP.NET", null, "Backend Framework", "CONFIRMED", "Header x-powered-by: " + poweredBy));
        }

        // Next.js
        if (lower.contains("next.js") || lower.contains("nextjs")) {
            recordTech(detectedMap, new DetectedTech("Next.js", null, "Backend Framework", "CONFIRMED", "Header x-powered-by: " + poweredBy));
        }
    }

    private void inspectGeneratorHeader(String generator, Map<String, DetectedTech> detectedMap) {
        String lower = generator.toLowerCase(Locale.ROOT);
        if (lower.contains("wordpress")) {
            Matcher m = WORDPRESS_META_PATTERN.matcher(generator);
            String ver = m.find() ? m.group(1) : null;
            recordTech(detectedMap, new DetectedTech("WordPress", cleanVersion(ver), "CMS", "CONFIRMED", "Header x-generator: " + generator));
        } else if (lower.contains("drupal")) {
            Matcher m = DRUPAL_META_PATTERN.matcher(generator);
            String ver = m.find() ? m.group(1) : null;
            recordTech(detectedMap, new DetectedTech("Drupal", cleanVersion(ver), "CMS", "CONFIRMED", "Header x-generator: " + generator));
        } else if (lower.contains("joomla")) {
            Matcher m = JOOMLA_META_PATTERN.matcher(generator);
            String ver = m.find() ? m.group(1) : null;
            recordTech(detectedMap, new DetectedTech("Joomla", cleanVersion(ver), "CMS", "CONFIRMED", "Header x-generator: " + generator));
        } else if (lower.contains("ghost")) {
            Matcher m = GHOST_META_PATTERN.matcher(generator);
            String ver = m.find() ? m.group(1) : null;
            recordTech(detectedMap, new DetectedTech("Ghost", cleanVersion(ver), "CMS", "CONFIRMED", "Header x-generator: " + generator));
        }
    }

    private void inspectCookies(List<ParsedCookie> cookies, Map<String, DetectedTech> detectedMap) {
        if (cookies == null || cookies.isEmpty()) {
            return;
        }

        for (ParsedCookie cookie : cookies) {
            String name = cookie.name();
            String lower = name.toLowerCase(Locale.ROOT);

            // Java / Servlet
            if ("jsessionid".equals(lower)) {
                recordTech(detectedMap, new DetectedTech("Java / Servlet", null, "Backend Runtime", "PROBABLE", "Cookie: " + name));
            }

            // PHP
            if ("phpsessid".equals(lower)) {
                recordTech(detectedMap, new DetectedTech("PHP", null, "Backend Runtime", "CONFIRMED", "Cookie: " + name));
            }

            // Django
            if ("csrftoken".equals(lower) || "sessionid".equals(lower)) {
                recordTech(detectedMap, new DetectedTech("Django", null, "Backend Framework", "TENTATIVE", "Cookie: " + name));
            }

            // Laravel
            if ("laravel_session".equals(lower) || "xsrf-token".equals(lower)) {
                String conf = "laravel_session".equals(lower) ? "PROBABLE" : "TENTATIVE";
                recordTech(detectedMap, new DetectedTech("Laravel", null, "Backend Framework", conf, "Cookie: " + name));
            }

            // Ruby on Rails
            if (lower.contains("_rails_session") || "_session_id".equals(lower)) {
                recordTech(detectedMap, new DetectedTech("Ruby on Rails", null, "Backend Framework", "CONFIRMED", "Cookie: " + name));
            }

            // WordPress
            if (lower.startsWith("wp-settings-") || lower.startsWith("wordpress_")) {
                recordTech(detectedMap, new DetectedTech("WordPress", null, "CMS", "CONFIRMED", "Cookie: " + name));
            }
        }
    }

    private void inspectBodyAndDom(String bodyText, String baseUrl, Map<String, DetectedTech> detectedMap) {
        if (bodyText == null || bodyText.isBlank()) {
            return;
        }

        // Spring Boot Whitelabel Error Page check
        if (bodyText.contains("Whitelabel Error Page")) {
            recordTech(detectedMap, new DetectedTech("Spring Boot", null, "Backend Framework", "PROBABLE", "DOM marker: Whitelabel Error Page"));
        }

        Document doc = Jsoup.parse(bodyText, baseUrl);

        // 1. Meta generator tags
        Elements metaGenerators = doc.select("meta[name=generator], meta[name=GENERATOR]");
        for (Element meta : metaGenerators) {
            String content = meta.attr("content").trim();
            if (content.isBlank()) {
                continue;
            }
            String lower = content.toLowerCase(Locale.ROOT);
            if (lower.contains("wordpress")) {
                Matcher m = WORDPRESS_META_PATTERN.matcher(content);
                String ver = m.find() ? m.group(1) : null;
                recordTech(detectedMap, new DetectedTech("WordPress", cleanVersion(ver), "CMS", "CONFIRMED", "Meta generator: " + content));
            } else if (lower.contains("drupal")) {
                Matcher m = DRUPAL_META_PATTERN.matcher(content);
                String ver = m.find() ? m.group(1) : null;
                recordTech(detectedMap, new DetectedTech("Drupal", cleanVersion(ver), "CMS", "CONFIRMED", "Meta generator: " + content));
            } else if (lower.contains("joomla")) {
                Matcher m = JOOMLA_META_PATTERN.matcher(content);
                String ver = m.find() ? m.group(1) : null;
                recordTech(detectedMap, new DetectedTech("Joomla", cleanVersion(ver), "CMS", "CONFIRMED", "Meta generator: " + content));
            } else if (lower.contains("ghost")) {
                Matcher m = GHOST_META_PATTERN.matcher(content);
                String ver = m.find() ? m.group(1) : null;
                recordTech(detectedMap, new DetectedTech("Ghost", cleanVersion(ver), "CMS", "CONFIRMED", "Meta generator: " + content));
            }
        }

        // 2. Script & Link URLs
        Elements scripts = doc.select("script[src]");
        for (Element script : scripts) {
            String src = script.attr("src").trim();
            inspectAssetUrl(src, detectedMap);
        }

        Elements links = doc.select("link[href]");
        for (Element link : links) {
            String href = link.attr("href").trim();
            inspectAssetUrl(href, detectedMap);
        }

        // 3. DOM Attributes & Indicators
        // Vue data-v-* attributes
        boolean hasVueAttribute = doc.select("*").stream()
                .anyMatch(el -> el.attributes().asList().stream().anyMatch(a -> a.getKey().startsWith("data-v-")));
        if (hasVueAttribute) {
            recordTech(detectedMap, new DetectedTech("Vue.js", null, "Frontend Framework", "CONFIRMED", "DOM attribute: data-v-*"));
        }

        // Angular / AngularJS ng-version & ng-app
        Element ngVerEl = doc.selectFirst("[ng-version]");
        if (ngVerEl != null) {
            String ver = ngVerEl.attr("ng-version").trim();
            boolean isAngularJs = ver.startsWith("1.");
            String name = isAngularJs ? "AngularJS" : "Angular";
            recordTech(detectedMap, new DetectedTech(name, cleanVersion(ver), "Frontend Framework", "CONFIRMED", "DOM attribute: ng-version=" + ver));
        }

        if (doc.selectFirst("[ng-app]") != null) {
            recordTech(detectedMap, new DetectedTech("AngularJS", null, "Frontend Framework", "CONFIRMED", "DOM attribute: ng-app"));
        }
    }

    private void inspectAssetUrl(String url, Map<String, DetectedTech> detectedMap) {
        if (url == null || url.isBlank()) {
            return;
        }

        String lower = url.toLowerCase(Locale.ROOT);

        // WordPress path markers
        if (lower.contains("/wp-content/") || lower.contains("/wp-includes/")) {
            recordTech(detectedMap, new DetectedTech("WordPress", null, "CMS", "CONFIRMED", "Asset path: " + url));
        }

        // jQuery
        if (lower.contains("jquery")) {
            Matcher m = JQUERY_URL_PATTERN.matcher(url);
            String ver = null;
            if (m.find()) {
                ver = m.group(1) != null ? m.group(1) : m.group(2);
            }
            recordTech(detectedMap, new DetectedTech("jQuery", cleanVersion(ver), "Frontend Library", "CONFIRMED", "Script src: " + url));
        }

        // Vue.js
        if (lower.contains("vue") && (lower.contains("vue.js") || lower.contains("vue.min.js")
                || lower.contains("vue.global.js") || lower.contains("/vue@") || lower.contains("/vue/"))) {
            Matcher m = VUE_URL_PATTERN.matcher(url);
            String ver = m.find() ? m.group(1) : null;
            recordTech(detectedMap, new DetectedTech("Vue.js", cleanVersion(ver), "Frontend Framework", "CONFIRMED", "Script src: " + url));
        }

        // AngularJS / Angular
        if (lower.contains("angular")) {
            Matcher m = ANGULAR_URL_PATTERN.matcher(url);
            String ver = null;
            if (m.find()) {
                ver = m.group(1) != null ? m.group(1) : m.group(2);
            }
            boolean isAngularJs = (ver != null && ver.startsWith("1.")) || lower.contains("angularjs") || lower.contains("angular.min.js");
            String name = isAngularJs ? "AngularJS" : "Angular";
            recordTech(detectedMap, new DetectedTech(name, cleanVersion(ver), "Frontend Framework", "CONFIRMED", "Script src: " + url));
        }

        // Bootstrap
        if (lower.contains("bootstrap")) {
            Matcher m = BOOTSTRAP_URL_PATTERN.matcher(url);
            String ver = m.find() ? m.group(1) : null;
            recordTech(detectedMap, new DetectedTech("Bootstrap", cleanVersion(ver), "Frontend Library", "CONFIRMED", "Asset: " + url));
        }

        // React
        if (lower.contains("react.production.min.js") || lower.contains("react-dom") || lower.contains("react.development.js")) {
            recordTech(detectedMap, new DetectedTech("React", null, "Frontend Framework", "CONFIRMED", "Script src: " + url));
        }

        // Next.js
        if (lower.contains("/_next/static/") || lower.contains("/_next/")) {
            recordTech(detectedMap, new DetectedTech("Next.js", null, "Backend Framework", "CONFIRMED", "Asset path: " + url));
        }
    }

    private void recordTech(Map<String, DetectedTech> detectedMap, DetectedTech newTech) {
        if (newTech == null || newTech.name == null || newTech.name.isBlank()) {
            return;
        }

        DetectedTech existing = detectedMap.get(newTech.name);
        if (existing == null) {
            detectedMap.put(newTech.name, newTech);
            return;
        }

        // Merge: select highest confidence, non-null version, and most specific evidence
        String bestConfidence = compareConfidence(existing.confidence, newTech.confidence) >= 0 ? existing.confidence : newTech.confidence;
        String bestVersion = (existing.version != null && !existing.version.isBlank()) ? existing.version : newTech.version;
        String bestEvidence = (existing.version != null && !existing.version.isBlank()) ? existing.evidence : newTech.evidence;

        detectedMap.put(newTech.name, new DetectedTech(newTech.name, bestVersion, existing.category, bestConfidence, bestEvidence));
    }

    private int compareConfidence(String c1, String c2) {
        return Integer.compare(confidenceWeight(c1), confidenceWeight(c2));
    }

    private int confidenceWeight(String conf) {
        if ("CONFIRMED".equalsIgnoreCase(conf)) return 3;
        if ("PROBABLE".equalsIgnoreCase(conf)) return 2;
        return 1; // TENTATIVE or others
    }

    private String cleanVersion(String ver) {
        if (ver == null || ver.isBlank()) {
            return null;
        }
        String cleaned = ver.trim().replaceAll("^[vV]", "").replaceAll("[.,;]+$", "");
        return cleaned.isBlank() ? null : cleaned;
    }

    private record DetectedTech(String name, String version, String category, String confidence, String evidence) {}
}
