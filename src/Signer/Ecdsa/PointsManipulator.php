<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

/**
 * @internal
 */
interface PointsManipulator
{
    public function fromEcPoint(string $signature, int $length): string;

    public function toEcPoint(string $points, int $length): string;
}
