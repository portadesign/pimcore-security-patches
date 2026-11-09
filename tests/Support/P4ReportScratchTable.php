<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait P4ReportScratchTable
{
    protected function reportTable(): string
    {
        return 'pd_sec_p4_report_scratch';
    }

    protected function createReportScratchTable(): void
    {
        $db = \Pimcore\Db::get();
        $db->executeStatement('DROP TABLE IF EXISTS `' . $this->reportTable() . '`');
        $db->executeStatement('CREATE TABLE `' . $this->reportTable() . '` (id INT NOT NULL PRIMARY KEY, note VARCHAR(100))');

        foreach ([[1, 'plain'], [2, 'other']] as [$id, $note]) {
            $db->insert($this->reportTable(), ['id' => $id, 'note' => $note]);
        }
    }

    protected function dropReportScratchTable(): void
    {
        \Pimcore\Db::get()->executeStatement('DROP TABLE IF EXISTS `' . $this->reportTable() . '`');
    }
}
