<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

final class P2StubGridColumn implements \Pimcore\DataObject\GridColumnConfig\ConfigElementInterface
{
    public function __construct(private readonly mixed $value)
    {
    }

    public function getLabel()
    {
        return 'stub';
    }

    public function getLabeledValue($element)
    {
        $result = new \stdClass();
        $result->label = 'stub';
        $result->value = $this->value;

        return $result;
    }
}
