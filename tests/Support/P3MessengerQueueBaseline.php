<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait P3MessengerQueueBaseline
{
    private int $highestMessengerIdBefore = 0;

    protected function recordMessengerQueueBaseline(): void
    {
        $this->highestMessengerIdBefore = (int) \Pimcore\Db::get()->fetchOne('SELECT COALESCE(MAX(id), 0) FROM messenger_messages');
    }

    protected function purgeMessengerQueueSinceBaseline(): void
    {
        \Pimcore\Db::get()->executeStatement('DELETE FROM messenger_messages WHERE id > ?', [$this->highestMessengerIdBefore]);
    }
}
