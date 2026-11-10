<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait MainDomainFixture
{
    private const FIXTURE_DOMAIN = 'reset-mail.example.test';

    private string $domain = '';

    private ?array $originalSystemSettings = null;

    protected function ensureDomain(): void
    {
        $settings = \Pimcore\SystemSettingsConfig::get();
        $this->domain = (string) ($settings['general']['domain'] ?? '');

        if ('' !== $this->domain) {
            return;
        }

        $this->originalSystemSettings = $settings;
        $this->domain = self::FIXTURE_DOMAIN;
        $settings['general']['domain'] = self::FIXTURE_DOMAIN;
        $this->systemSettings()->testSave($settings);
    }

    protected function restoreDomain(): void
    {
        if (null !== $this->originalSystemSettings) {
            $this->systemSettings()->testSave($this->originalSystemSettings);
            $this->originalSystemSettings = null;
        }
    }

    private function systemSettings(): \Pimcore\SystemSettingsConfig
    {
        $service = \Pimcore::getContainer()->get(\Pimcore\SystemSettingsConfig::class);
        \assert($service instanceof \Pimcore\SystemSettingsConfig);

        return $service;
    }
}
