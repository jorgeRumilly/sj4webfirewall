<?php

if (!defined('_PS_VERSION_')) {
    exit;
}

class Sj4webFirewallUserAgentMatcher
{
    /**
     * Verifie si un user-agent correspond a au moins une signature.
     */
    public static function matchesAny($userAgent, array $patterns)
    {
        foreach ($patterns as $pattern) {
            if (self::matches($userAgent, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Retourne la premiere signature qui matche un user-agent.
     */
    public static function detect($userAgent, array $patterns)
    {
        foreach ($patterns as $pattern) {
            if (self::matches($userAgent, $pattern)) {
                return trim((string) $pattern);
            }
        }

        return null;
    }

    /**
     * Nettoie une liste de signatures et supprime les motifs trop dangereux.
     *
     * @param string $listType safe|malicious
     *
     * @return array<int, string>
     */
    public static function sanitizeList(array $patterns, $listType = 'safe')
    {
        $clean = [];
        $blacklist = $listType === 'malicious' ? self::getUnsafeMaliciousPatterns() : [];

        foreach ($patterns as $pattern) {
            $pattern = trim(Tools::strtolower((string) $pattern));
            if ($pattern === '' || in_array($pattern, $blacklist, true)) {
                continue;
            }

            $clean[$pattern] = $pattern;
        }

        return array_values($clean);
    }

    /**
     * Fusionne une liste existante avec les signatures safe recommandees.
     *
     * @return array<int, string>
     */
    public static function mergeRecommendedSafeBots(array $patterns)
    {
        $merged = self::sanitizeList($patterns, 'safe');

        foreach (self::getRecommendedSafeBots() as $pattern) {
            $merged[] = $pattern;
        }

        return self::sanitizeList($merged, 'safe');
    }

    /**
     * Indique si une signature correspond au user-agent.
     *
     * Les petits tokens sont encadres pour eviter les faux positifs du type
     * `sf` detecte dans `fbcr/sfr`.
     */
    protected static function matches($userAgent, $pattern)
    {
        $userAgent = (string) $userAgent;
        $pattern = trim((string) $pattern);

        if ($userAgent === '' || $pattern === '') {
            return false;
        }

        if (self::looksLikeRegex($pattern)) {
            return (bool) preg_match('~' . $pattern . '~i', $userAgent);
        }

        $normalizedPattern = Tools::strtolower($pattern);
        $normalizedUserAgent = Tools::strtolower($userAgent);

        if (Tools::strlen($normalizedPattern) <= 3) {
            return (bool) preg_match(
                '/(^|[^a-z0-9])' . preg_quote($normalizedPattern, '/') . '([^a-z0-9]|$)/i',
                $normalizedUserAgent
            );
        }

        return strpos($normalizedUserAgent, $normalizedPattern) !== false;
    }

    /**
     * Repere les signatures qui ressemblent a des expressions regulieres.
     */
    protected static function looksLikeRegex($pattern)
    {
        return (bool) preg_match('/[\\\\\\[\\]\\(\\)\\{\\}\\?\\+\\*\\|\\^\\$]/', (string) $pattern);
    }

    /**
     * Signatures safe a injecter sur les configs existantes.
     *
     * @return array<int, string>
     */
    protected static function getRecommendedSafeBots()
    {
        return [
            'googlebot-image',
            'googleother',
            'google-inspectiontool',
            'google-xrawler',
            'facebookexternalhit',
            'meta-externalagent',
            'meta-externalads',
            'meta-webindexer',
            'tiktokspider',
            'bytespider',
            'mojeekbot',
            'uptimerobot',
            'chrome privacy preserving prefetch proxy',
        ];
    }

    /**
     * Motifs legacy trop larges, source de faux positifs.
     *
     * @return array<int, string>
     */
    protected static function getUnsafeMaliciousPatterns()
    {
        return [
            'sf',
        ];
    }
}
