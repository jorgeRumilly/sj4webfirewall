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

//        $this->setTemplate('module:sj4webfirewall/views/templates/admin/firewall_logs.tpl');
//        $template_path = '../../../../modules/preparationcommande/views/templates/admin/sj4webvalidateorder/';
//        $this->setTemplate(_PS_MODULE_DIR_ . 'sj4webfirewall/views/templates/admin/firewall_logs.tpl');
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
}
