#!/usr/bin/env php
<?php

declare(strict_types=1);

$root = dirname(path: __DIR__);
$options = getopt(short_options: '', long_options: ['bump', 'tooling::']);

/**
 * @var array{
 *     products: array<string, list<string>>,
 *     advisories: list<array{
 *         cve: string,
 *         ghsa?: string,
 *         pksa: string|null,
 *         status: string,
 *         package: string,
 *         patch?: string,
 *         notes?: string,
 *         justification?: string,
 *         impact?: string,
 *         action?: string,
 *         reason: string
 *     }>
 * } $manifest
 */
$manifest = json_decode(json: (string) file_get_contents(filename: $root . '/advisories.json'), associative: true, flags: JSON_THROW_ON_ERROR);

$vexPath = $root . '/vex.openvex.json';
$version = 1;
$tooling = 'pimcore-security-patches';
if (is_file(filename: $vexPath)) {
    $previous = json_decode(json: (string) file_get_contents(filename: $vexPath), associative: true, flags: JSON_THROW_ON_ERROR);
    if (is_array($previous)) {
        $version = is_int($previous['version'] ?? null) ? $previous['version'] + (isset($options['bump']) ? 1 : 0) : 1;
        $tooling = is_string($previous['tooling'] ?? null) ? $previous['tooling'] : $tooling;
    }
}
if (is_string($options['tooling'] ?? null)) {
    $tooling = 'pimcore-security-patches ' . $options['tooling'];
}

$timestamp = gmdate(format: 'Y-m-d\TH:i:s\Z');
$statements = [];
$auditIgnore = [];

foreach ($manifest['advisories'] as $advisory) {
    if (is_string($advisory['pksa'])) {
        $auditIgnore[$advisory['pksa']] = $advisory['reason'];
    } elseif (str_starts_with(haystack: $advisory['cve'], needle: 'CVE-')) {
        $auditIgnore[$advisory['cve']] = $advisory['reason'];
        if (is_string($advisory['ghsa'] ?? null)) {
            $auditIgnore[$advisory['ghsa']] = $advisory['reason'];
        }
    }

    if (!in_array(needle: $advisory['status'], haystack: ['fixed', 'affected', 'not_affected'], strict: true)) {
        continue;
    }

    $products = [];
    foreach ($manifest['products'][$advisory['package']] as $productVersion) {
        foreach ([$productVersion, 'v' . $productVersion] as $purlVersion) {
            $purl = sprintf('pkg:composer/%s@%s', $advisory['package'], $purlVersion);
            $products[] = ['@id' => $purl, 'identifiers' => ['purl' => $purl]];
        }
    }

    $vulnerability = ['name' => $advisory['cve']];
    $aliases = array_values(array: array_filter(array: [$advisory['pksa'], $advisory['ghsa'] ?? null], callback: is_string(...)));
    if ([] !== $aliases) {
        $vulnerability['aliases'] = $aliases;
    }

    $statement = ['vulnerability' => $vulnerability, 'products' => $products, 'status' => $advisory['status']];
    if ('not_affected' === $advisory['status']) {
        $statement['justification'] = $advisory['justification'] ?? '';
        $statement['impact_statement'] = $advisory['impact'] ?? '';
    } else {
        $statement['status_notes'] = trim(string: sprintf(
            '%s by %s. %s',
            'fixed' === $advisory['status'] ? 'Fixed' : 'Partially fixed',
            $advisory['patch'] ?? '',
            $advisory['notes'] ?? '',
        ));
    }
    if ('affected' === $advisory['status']) {
        $statement['action_statement'] = $advisory['action'] ?? '';
    }
    $statements[] = $statement;
}

$flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

file_put_contents(filename: $vexPath, data: json_encode(value: [
    '@context' => 'https://openvex.dev/ns/v0.2.0',
    '@id' => 'https://github.com/portadesign/pimcore-11-security-patches/vex.openvex.json',
    'author' => 'Portadesign',
    'timestamp' => $timestamp,
    'last_updated' => $timestamp,
    'version' => $version,
    'tooling' => $tooling,
    'statements' => $statements,
], flags: $flags) . "\n");

ksort(array: $auditIgnore);
file_put_contents(filename: $root . '/audit-ignore.json', data: json_encode(value: [
    'config' => [
        'audit' => ['ignore' => $auditIgnore],
        'policy' => ['advisories' => ['ignore-id' => $auditIgnore]],
    ],
], flags: $flags) . "\n");
