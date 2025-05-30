<?php

class AdminSj4webFirewallLogController extends ModuleAdminController
{
    public function __construct()
    {
        $this->bootstrap = true;
        $this->className = 'AdminSj4webFirewallLogController';
        $this->table = 'sj4web_firewall_log';
        $this->lang = false;
        $this->explicitSelect = false;
        $this->deleted = false;
        $this->display = 'list';
        $this->module = Module::getInstanceByName('sj4webfirewall');

        parent::__construct();
    }

    public function initContent()
    {
        parent::initContent();

        $this->meta_title = $this->trans('IP Logs - sj4webfirewall', [], 'Modules.Sj4webfirewall.Admin');
        // https://chatgpt.com/share/680686b5-e248-8013-a918-38d62d960f04
        $filepath = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/ip_scores.json';
        $entries = [];

        if (file_exists($filepath)) {
            $json = file_get_contents($filepath);
            $data = json_decode($json, true);

            if (is_array($data)) {
                foreach ($data as $ip => $info) {
                    $entries[] = [
                        'ip' => $ip,
                        'score' => (int) $info['score'],
                        'count' => $info['count'] ?? 0,
                        'updated_at' => isset($info['updated_at']) ? date('Y-m-d H:i:s', $info['updated_at']) : '',
                        'status' => $this->getStatusFromScore((int) $info['score']),
                        'log' => isset($info['log']) ? (array) $info['log'] : [],
                        'whitelisted' => !empty($info['whitelisted']),
                    ];
                }
            }
        }

        $this->context->smarty->assign([
            'firewall_logs' => $entries,
            'token' => Tools::getAdminTokenLite('AdminSj4webFirewallLog'),
        ]);

        $this->setTemplate('firewall_logs.tpl');

    }

    protected function getStatusFromScore($score)
    {
        $config = [];
        foreach (array_keys(require _PS_MODULE_DIR_ . 'sj4webfirewall/config/default_config.php') as $key) {
            $val = Configuration::get($key);
            $config[$key] = $val;
        }

        if ($score <= (int) $config['SJ4WEB_FW_SCORE_LIMIT_BLOCK']) {
            return 'blocked';
        }
        if ($score <= (int) $config['SJ4WEB_FW_SCORE_LIMIT_SLOW']) {
            return 'slow';
        }
        return 'normal';
    }

    public function postProcess()
    {
        parent::postProcess();

        $action = Tools::getValue('action');
        $ip = Tools::getValue('ip');

        if ($action && $ip) {
            $filepath = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/ip_scores.json';
            $data = [];

            if (file_exists($filepath)) {
                $data = json_decode(file_get_contents($filepath), true);
            }

            $whitelist = json_decode(Configuration::get('SJ4WEB_FW_WHITELIST_IPS'), true) ?: [];

            switch ($action) {
                case 'resetScore':
                    if (isset($data[$ip])) {
                        $data[$ip]['score'] = 0;
                    }
                    break;

                case 'deleteIp':
                    if (isset($data[$ip])) {
                        unset($data[$ip]);
                    }
                    break;

                case 'whitelist':
                    if (isset($data[$ip])) {
                        $data[$ip]['whitelisted'] = true;
                        if (!in_array($ip, $whitelist)) {
                            $whitelist[] = $ip;
                            Configuration::updateValue('SJ4WEB_FW_WHITELIST_IPS', json_encode(array_values($whitelist)));
                        }
                    }
                    break;

                case 'unwhitelist':
                    if (isset($data[$ip])) {
                        unset($data[$ip]['whitelisted']);
                        $whitelist = array_filter($whitelist, fn($item) => trim($item) !== $ip);
                        Configuration::updateValue('SJ4WEB_FW_WHITELIST_IPS', json_encode(array_values($whitelist)));
                    }
                    break;
            }

            file_put_contents($filepath, json_encode($data, JSON_PRETTY_PRINT));

            Tools::redirectAdmin(self::$currentIndex . '&token=' . Tools::getAdminTokenLite('AdminSj4webFirewallLog'));
        }
    }

}
