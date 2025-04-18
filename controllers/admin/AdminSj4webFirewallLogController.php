<?php

class AdminSj4webFirewallLogController extends ModuleAdminController
{
    public function __construct()
    {
        $this->bootstrap = true;
        $this->module = Module::getInstanceByName('sj4webfirewall');
        $this->className = 'AdminSj4webFirewallLog';
        $this->lang = false;
        $this->table = 'firewall_log';
        $this->context = Context::getContext();

        parent::__construct();
    }

    public function initContent()
    {
        parent::initContent();

        $filepath = _PS_MODULE_DIR_.'sj4webfirewall/logs/ip_scores.json';
        $entries = [];

        if (file_exists($filepath)) {
            $json = file_get_contents($filepath);
            $data = json_decode($json, true);

            foreach ($data as $ip => $info) {
                $entries[] = [
                    'ip' => $ip,
                    'score' => $info['score'],
                    'updated_at' => date('Y-m-d H:i:s', $info['updated_at']),
                    'status' => $this->getStatusFromScore($info['score']),
                    'log' => $info['log'],
                ];
            }
        }

        $this->context->smarty->assign([
            'firewall_logs' => $entries,
        ]);

        $this->setTemplate('module:sj4webfirewall/views/templates/admin/firewall_logs.tpl');
    }

    protected function getStatusFromScore($score)
    {
        $config = [];
        foreach (array_keys(require _PS_MODULE_DIR_.'sj4webfirewall/config/default_config.php') as $key) {
            $val = Configuration::get($key);
            $config[$key] = $val;
        }

        if ($score <= $config['SJ4WEB_FW_SCORE_LIMIT_BLOCK']) {
            return 'blocked';
        }
        if ($score <= $config['SJ4WEB_FW_SCORE_LIMIT_SLOW']) {
            return 'slow';
        }
        return 'normal';
    }
}
