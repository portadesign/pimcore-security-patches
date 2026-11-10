<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait RejectedSerializedPayloads
{
    /**
     * @return array<string, array{string}>
     */
    public static function rejectedSerializedPayloadProvider(): array
    {
        $canary = \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class;
        $length = strlen($canary);

        return [
            'enum case' => [serialize(\Portadesign\PimcoreSecurityPatches\Tests\Support\ForeignEnum::Gadget)],
            'enum case nested in array' => [serialize(['wrapper' => \Portadesign\PimcoreSecurityPatches\Tests\Support\ForeignEnum::Gadget])],
            'custom serialised class' => ['C:' . $length . ':"' . $canary . '":3:{abc}'],
            'custom serialised class nested in array' => ['a:1:{i:0;C:' . $length . ':"' . $canary . '":3:{abc}}'],
            'zero-padded length' => ['O:0' . $length . ':"' . $canary . '":0:{}'],
            'zero-padded length nested in array' => ['a:1:{i:0;O:0' . $length . ':"' . $canary . '":0:{}}'],
            'signed property count' => ['O:' . $length . ':"' . $canary . '":+0:{}'],
            'signed property count nested in array' => ['a:1:{i:0;O:' . $length . ':"' . $canary . '":+0:{}}'],
            'signed array key before the object' => ['a:1:{i:+0;O:' . $length . ':"' . $canary . '":0:{}}'],
            'upper-case class name' => ['O:' . $length . ':"' . strtoupper($canary) . '":0:{}'],
            'lower-case class name' => ['O:' . $length . ':"' . strtolower($canary) . '":0:{}'],
            'bare stdClass' => [serialize(new \stdClass())],
        ];
    }
}
