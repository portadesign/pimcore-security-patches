<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

final class StubPrintProcessor extends \Pimcore\Web2Print\Processor
{
    protected function buildPdf(\Pimcore\Model\Document\PrintAbstract $document, $config)
    {
        return '';
    }

    public function getProcessingOptions()
    {
        return [];
    }

    public function getPdfFromString($html, $params = [], $returnFilePath = false)
    {
        return '';
    }

    /**
     * @param array<string, mixed> $params
     */
    public function renderHtml(string $html, array $params = []): string
    {
        return $this->processHtml($html, $params);
    }
}
