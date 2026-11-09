<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait HostResidueGuard
{
    private int $residueHighestMessageId = 0;

    private int $residueHighestVersionId = 0;

    /**
     * @var array<string, int>
     */
    private array $residueHighestElementIds = [];

    #[\PHPUnit\Framework\Attributes\Before]
    public function recordHostResidueBaseline(): void
    {
        \Pimcore\Model\Version::disable();

        $db = \Pimcore\Db::get();
        $this->residueHighestMessageId = (int) $db->fetchOne('SELECT COALESCE(MAX(id), 0) FROM messenger_messages');
        $this->residueHighestVersionId = (int) $db->fetchOne('SELECT COALESCE(MAX(id), 0) FROM versions');
        $this->residueHighestElementIds = [];

        foreach (['asset' => ['assets', 'id'], 'document' => ['documents', 'id'], 'object' => ['objects', 'o_id']] as $type => [$table, $column]) {
            $this->residueHighestElementIds[$type] = (int) $db->fetchOne(sprintf('SELECT COALESCE(MAX(%s), 0) FROM %s', $column, $table));
        }
    }

    #[\PHPUnit\Framework\Attributes\After]
    public function removeHostResidue(): void
    {
        \Pimcore\Model\Version::enable();

        foreach ($this->residueHighestElementIds as $type => $highestId) {
            $versions = new \Pimcore\Model\Version\Listing();
            $versions->setCondition('id > ? AND ctype = ? AND cid > ?', [$this->residueHighestVersionId, $type, $highestId]);
            foreach ($versions->load() as $version) {
                $version->delete();
            }
        }

        $this->removeResidueMessages();

        (new \ReflectionProperty(\Pimcore\Translation\TranslationEntriesDumper::class, 'translations'))->setValue(null, []);
    }

    private function removeResidueMessages(): void
    {
        $db = \Pimcore\Db::get();

        if ('1' === getenv('PD_TEST_HOST_DISPOSABLE')) {
            $db->executeStatement('DELETE FROM messenger_messages WHERE id > ?', [$this->residueHighestMessageId]);

            return;
        }

        $ownIds = [];
        foreach ($db->fetchAllAssociative('SELECT id, body FROM messenger_messages WHERE id > ?', [$this->residueHighestMessageId]) as $row) {
            if ($this->residueMessageTargetsNewElement(stripcslashes((string) $row['body']))) {
                $ownIds[] = (int) $row['id'];
            }
        }

        if ([] !== $ownIds) {
            $db->executeStatement('DELETE FROM messenger_messages WHERE id IN (?)', [$ownIds], [\Doctrine\DBAL\Connection::PARAM_INT_ARRAY]);
        }
    }

    private function residueMessageTargetsNewElement(string $serialized): bool
    {
        if (1 !== preg_match('/Pimcore\\\\Messenger\\\\(\w+)":/', $serialized, $class)
            || 1 !== preg_match('/"\0\*\0(?:id|elementId)";i:(\d+);/', $serialized, $id)) {
            return false;
        }

        if (1 === preg_match('/"\0\*\0(?:type|elementType)";s:\d+:"(\w+)";/', $serialized, $type)) {
            $elementType = $type[1];
        } else {
            $elementType = match (true) {
                1 === preg_match('/^(?:AssetUpdateTasks|AssetPreviewImage|OptimizeImage|VideoConvert)/', $class[1]) => 'asset',
                'GeneratePagePreviewMessage' === $class[1] => 'document',
                default => '',
            };
        }

        return isset($this->residueHighestElementIds[$elementType]) && (int) $id[1] > $this->residueHighestElementIds[$elementType];
    }
}
