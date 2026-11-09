<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait HostResidueGuard
{
    private int $residueHighestMessageId = 0;

    private int $residueHighestVersionId = 0;

    #[\PHPUnit\Framework\Attributes\Before]
    public function recordHostResidueBaseline(): void
    {
        \Pimcore\Model\Version::disable();

        $db = \Pimcore\Db::get();
        $this->residueHighestMessageId = (int) $db->fetchOne('SELECT COALESCE(MAX(id), 0) FROM messenger_messages');
        $this->residueHighestVersionId = (int) $db->fetchOne('SELECT COALESCE(MAX(id), 0) FROM versions');
    }

    #[\PHPUnit\Framework\Attributes\After]
    public function removeHostResidue(): void
    {
        \Pimcore\Model\Version::enable();

        $versions = new \Pimcore\Model\Version\Listing();
        $versions->setCondition('id > ?', [$this->residueHighestVersionId]);
        foreach ($versions->load() as $version) {
            $version->delete();
        }

        \Pimcore\Db::get()->executeStatement('DELETE FROM messenger_messages WHERE id > ?', [$this->residueHighestMessageId]);

        (new \ReflectionProperty(\Pimcore\Translation\TranslationEntriesDumper::class, 'translations'))->setValue(null, []);
    }
}
