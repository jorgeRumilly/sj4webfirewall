<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

use GeoIp2\Database\Reader;

class FirewallGeo
{
    protected $reader;

    public function __construct()
    {
        $mmdbPath = __DIR__ . '/../geo/GeoLite2-Country.mmdb';
        if (file_exists($mmdbPath)) {
            $this->reader = new Reader($mmdbPath);
        }
    }

    public function getCountryCode($ip)
    {
        if (!$this->reader) {
            return null;
        }

        try {
            $record = $this->reader->country($ip);
            return $record->country->isoCode;
        } catch (\Exception $e) {
            return null;
        }
    }
}
