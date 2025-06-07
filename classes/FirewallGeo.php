<?php
if (!defined('_PS_VERSION_')) {
    exit;
}
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/vendor/autoload.php';
use GeoIp2\Database\Reader;

class FirewallGeo
{
    protected $reader;

    public function __construct()
    {
        $mmdbPath = _PS_MODULE_DIR_ . 'sj4webfirewall/geo/GeoLite2-Country.mmdb';
        if (file_exists($mmdbPath)) {
            $this->reader = new Reader($mmdbPath);
        }
    }

    public function getCountryCode($ip)
    {
        if (!$this->reader) {
            throw new \Exception('GeoIP database not found.');
        }

        try {
            $record = $this->reader->country($ip);
            return $record->country->isoCode;
        } catch (\Exception $e) {
            throw new \Exception('Error retrieving country code: ' . $e->getMessage());
        }
    }
}
