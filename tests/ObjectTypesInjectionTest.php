<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
final class ObjectTypesInjectionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P3SandboxRendering;

    private const PARENT_KEY = 'pd-sec-p3-objecttypes';

    private const PAYLOAD = "object') OR 1=1 OR o_type IN ('x";

    protected function setUp(): void
    {
        $this->deleteFixture();
        $parent = $this->createFolder(self::PARENT_KEY, 1);
        foreach (['child-a', 'child-b', 'empty'] as $key) {
            $this->createFolder($key, $parent->getId());
        }
    }

    protected function tearDown(): void
    {
        $this->disableSandbox();
        $this->deleteFixture();
    }

    public function testChildrenListingIgnoresInjectedObjectTypes(): void
    {
        $this->assertSame([], $this->keysOf($this->folder('empty')->getChildren([self::PAYLOAD])));
    }

    public function testSiblingListingIgnoresInjectedObjectTypes(): void
    {
        $this->assertSame([], $this->keysOf($this->folder('child-a')->getSiblings([self::PAYLOAD])));
    }

    public function testHasChildrenIgnoresInjectedObjectTypes(): void
    {
        $this->assertFalse($this->folder('empty')->hasChildren([self::PAYLOAD]));
    }

    public function testHasSiblingsIgnoresInjectedObjectTypes(): void
    {
        $this->assertFalse($this->folder('child-a')->hasSiblings([self::PAYLOAD]));
    }

    public function testChildAmountIgnoresInjectedObjectTypes(): void
    {
        $this->assertSame(0, $this->folder('empty')->getDao()->getChildAmount([self::PAYLOAD]));
    }

    public function testListingObjectTypesIgnoreInjection(): void
    {
        $listing = new \Pimcore\Model\DataObject\Listing();
        $listing->setCondition('o_parentId = ?', [$this->folder(self::PARENT_KEY)->getId()]);
        $listing->setObjectTypes([self::PAYLOAD]);

        $this->assertSame([], $this->keysOf($listing->load()));
    }

    public function testControlValidObjectTypesStillFilter(): void
    {
        $parent = $this->folder(self::PARENT_KEY);

        $this->assertSame(
            [
                'folder' => ['child-a', 'child-b', 'empty'],
                'object' => [],
                'has folder children' => true,
                'has object children' => false,
                'folder siblings of child-a' => ['child-b', 'empty'],
                'child amount folder' => 3,
                'child amount object' => 0,
            ],
            [
                'folder' => $this->keysOf($parent->getChildren(['folder'])),
                'object' => $this->keysOf($this->folder(self::PARENT_KEY)->getChildren(['object'])),
                'has folder children' => $this->folder(self::PARENT_KEY)->hasChildren(['folder']),
                'has object children' => $this->folder(self::PARENT_KEY)->hasChildren(['object']),
                'folder siblings of child-a' => $this->keysOf($this->folder('child-a')->getSiblings(['folder'])),
                'child amount folder' => $this->folder(self::PARENT_KEY)->getDao()->getChildAmount(['folder']),
                'child amount object' => $this->folder(self::PARENT_KEY)->getDao()->getChildAmount(['object']),
            ],
        );
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function sandboxedCallProvider(): array
    {
        return [
            'children' => ["{% set found = folder.getChildren(types) %}{{ found ? 'rows' : 'none' }}", 'empty', self::PARENT_KEY],
            'siblings' => ["{% set found = folder.getSiblings(types) %}{{ found ? 'rows' : 'none' }}", 'child-a', 'child-a'],
            'has children' => ["{{ folder.hasChildren(types) ? 'rows' : 'none' }}", 'empty', self::PARENT_KEY],
            'has siblings' => ["{{ folder.hasSiblings(types) ? 'rows' : 'none' }}", 'child-a', 'child-a'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('sandboxedCallProvider')]
    public function testSandboxedTemplateGetsNoRowsForInjectedObjectTypes(string $template, string $key): void
    {
        $rendered = $this->renderSandboxed($template, ['folder' => $this->folder($key), 'types' => [self::PAYLOAD]]);

        $this->assertSame('none', $rendered);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('sandboxedCallProvider')]
    public function testControlSandboxedTemplateStillSeesRowsForValidObjectTypes(string $template, string $injectedKey, string $validKey): void
    {
        $rendered = $this->renderSandboxed($template, ['folder' => $this->folder($validKey), 'types' => ['folder']]);

        $this->assertSame('rows', $rendered);
    }

    private function folder(string $key): \Pimcore\Model\DataObject\Folder
    {
        $path = self::PARENT_KEY === $key ? '/' . self::PARENT_KEY : '/' . self::PARENT_KEY . '/' . $key;
        $folder = \Pimcore\Model\DataObject\Folder::getByPath($path, ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\DataObject\Folder::class, $folder, 'fixture folder ' . $path);

        return $folder;
    }

    private function createFolder(string $key, int $parentId): \Pimcore\Model\DataObject\Folder
    {
        $folder = new \Pimcore\Model\DataObject\Folder();
        $folder->setKey($key);
        $folder->setParentId($parentId);
        $folder->setUserOwner(1);
        $folder->setUserModification(1);
        $folder->save();

        return $folder;
    }

    /**
     * @param list<\Pimcore\Model\DataObject\AbstractObject> $objects
     *
     * @return list<string>
     */
    private function keysOf(array $objects): array
    {
        $keys = array_map(static fn (\Pimcore\Model\DataObject\AbstractObject $object): string => $object->getKey(), $objects);
        sort($keys);

        return $keys;
    }

    private function deleteFixture(): void
    {
        \Pimcore\Model\DataObject\Folder::getByPath('/' . self::PARENT_KEY, ['force' => true])?->delete();
    }
}
