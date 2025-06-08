<?php

require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallStorage.php';

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

            if ((int)Tools::getValue('viewlogs') && Tools::getValue('ip')) {
                $this->renderLogsView(Tools::getValue('ip'));
                return;
            }


            if (is_array($data)) {
                // On charge FirewallStorage avec les bons seuils
                $storage = new FirewallStorage(
                    (int)Configuration::get('SJ4WEB_FW_SCORE_LIMIT_BLOCK'),
                    (int)Configuration::get('SJ4WEB_FW_SCORE_LIMIT_SLOW'),
                    (int)Configuration::get('SJ4WEB_FW_BLOCK_DURATION'),
                    (int)Configuration::get('SJ4WEB_FW_ALERT_THRESHOLD')
                );

                foreach ($data as $ip => $info) {
                    $entries[] = [
                        'ip' => $ip,
                        'country' => $info['country'] ?? '-',
                        'score' => (int)$info['score'],
                        'status' => $storage->getStatusForIp($ip), // Ici la vraie méthode
                        'count' => $info['count'] ?? 0,
                        'log' => isset($info['log']) ? (array)$info['log'] : [],
                        'last_log' => isset($info['log']) && count($info['log']) > 0
                            ? end($info['log'])['time'] . ' - ' . end($info['log'])['reason']
                            : '-',
                        'first_seen' => isset($info['first_seen']) ? date('Y-m-d H:i:s', $info['first_seen']) : '-',
                        'updated_at' => isset($info['updated_at']) ? date('Y-m-d H:i:s', $info['updated_at']) : '-',
                        'whitelisted' => !empty($info['whitelisted']),
                        'actions' => [], // Placeholder pour les actions
                    ];
                }
            }
        }
        // HelperList
        $helper = new HelperList();
        $helper->module = $this->module;
        $helper->shopLinkType = '';
        $helper->simple_header = false;
        $helper->identifier = 'ip';
//        $helper->actions = $this->getRowActions($entries[0] ?? []);
        $helper->title = $this->trans('Detected IPs History', [], 'Modules.Sj4webfirewall.Admin');
        $helper->table = 'firewall_logs';
        $helper->token = Tools::getAdminTokenLite('AdminSj4webFirewallLog');
        $helper->currentIndex = AdminController::$currentIndex;
        $helper->show_toolbar = true;

        $fields_list = [
            'ip' => [
                'title' => $this->trans('IP Address', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'filter_key' => 'ip'
            ],
            'country' => [
                'title' => $this->trans('Country', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'align' => 'center',
            ],
            'score' => [
                'title' => $this->trans('Score', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'number',
                'align' => 'center',
                'search' => false,
            ],
            'status' => [
                'title' => $this->trans('Status', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'select',
                'list' => [
                    ['normal' => $this->trans('Normal', [], 'Modules.Sj4webfirewall.Admin')],
                    ['slow' => $this->trans('Slow', [], 'Modules.Sj4webfirewall.Admin')],
                    ['blocked' => $this->trans('Blocked', [], 'Modules.Sj4webfirewall.Admin')],
                ],
                'filter_key' => 'status',
                'filter' => true,
                'callback' => 'getStatusLabel',
                'align' => 'center',
            ],
            'count' => [
                'title' => $this->trans('Visits', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'number',
                'align' => 'center',
                'search' => false,
            ],
            'first_seen' => [
                'title' => $this->trans('First Activity', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'datetime',
            ],
            'last_log' => [
                'title' => $this->trans('Last Log', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
            ],
            'updated_at' => [
                'title' => $this->trans('Last Activity', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'datetime',
            ],
            'actions' => [
                'title' => $this->trans('Actions', [], 'Modules.Sj4webfirewall.Admin'),
                'search' => false,
                'orderby' => false,
                'callback' => 'displayRowActions',
                'callback_object' => $this,
            ],

        ];
        $this->context->smarty->assign('content', $helper->generateList($entries, $fields_list));

    }
    //        $this->context->smarty->assign([
//            'firewall_logs' => $entries,
//            'token' => Tools::getAdminTokenLite('AdminSj4webFirewallLog'),
//        ]);
//
//        $this->setTemplate('firewall_logs.tpl');


    public function renderList()
    {
        $this->actions = ['resetScore', 'deleteIp', 'whitelist', 'unwhitelist', 'forceBlock', 'unblockIp', 'viewlogs'];

        return parent::renderList();
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
                        unset($data[$ip]['blocked_until']);
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
                case 'forceBlock':
                    if (isset($data[$ip])) {
                        $now = time();
                        $blockDuration = (int)Configuration::get('SJ4WEB_FW_BLOCK_DURATION');
                        $data[$ip]['blocked_until'] = $now + $blockDuration;
                    }
                    break;

                case 'unblockIp':
                    if (isset($data[$ip]) && isset($data[$ip]['blocked_until'])) {
                        unset($data[$ip]['blocked_until']);
                    }
                    break;

            }

            file_put_contents($filepath, json_encode($data, JSON_PRETTY_PRINT));

            Tools::redirectAdmin(self::$currentIndex . '&token=' . Tools::getAdminTokenLite('AdminSj4webFirewallLog'));
        }
    }

    public function displayRowActions($value, $entry)
    {
        $actions = [];
        $ip = urlencode($entry['ip']);
        $token = Tools::getAdminTokenLite('AdminSj4webFirewallLog');

        // Always available
        $actions[] = $this->displayResetScoreLink($token, $entry['ip']);
        $actions[] = $this->displayDeleteIpLink($token, $entry['ip']);
        // Only if whitelisted
        if (!empty($entry['whitelisted'])) {
            $actions[] = $this->displayUnwhitelistLink($token, $entry['ip']);
        } else {
            $actions[] = $this->displayWhitelistLink($token, $entry['ip']);
        }
        // Only if blocked
        if ($entry['status'] === 'blocked') {
            $actions[] = $this->displayUnblockLink($token, $entry['ip']);
        } else {
            $actions[] = $this->displayForceBlockLink($token, $entry['ip']);
        }
        $actions[] = $this->displayViewLogsLink($token, $entry['ip']);
        return '<div class="btn-group">' . implode(' ', $actions) . '</div>';
    }

    public function getStatusLabel($value, $entry)
    {
        $status = $entry['status'] ?? 'unknown';
        switch ($status) {
            case 'blocked':
                return '<span class="badge badge-danger">' . $this->trans('Blocked', [], 'Modules.Sj4webfirewall.Admin') . '</span>';
            case 'slow':
                return '<span class="badge badge-warning">' . $this->trans('Slow', [], 'Modules.Sj4webfirewall.Admin') . '</span>';
            default:
                return '<span class="badge badge-success">' . $this->trans('Normal', [], 'Modules.Sj4webfirewall.Admin') . '</span>';
        }
    }

    public function displayResetScoreLink($token, $id, $name = null)
    {
        $ip = urlencode($id);
        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=resetScore&ip=' . $ip . '" 
                   title="' . $this->trans('Reset score', [], 'Modules.Sj4webfirewall.Admin') . '"
                   class="btn btn-sm btn-outline-sjprimary"><i class="material-icons">restart_alt</i></a>';
    }

    public function displayDeleteIpLink($token, $id, $name = null)
    {
        $ip = urlencode($id);
        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=deleteIp&ip=' . $ip . '" 
            title="' . $this->trans('Delete IP', [], 'Modules.Sj4webfirewall.Admin') . '" onclick="return confirm(\'' . $this->trans('Delete this IP?', [], 'Modules.Sj4webfirewall.Admin') . '\');"
            class="btn btn-sm btn-outline-sjdanger"><i class="material-icons">delete</i></a>';
    }

    public function displayWhitelistLink($token, $id, $name = null)
    {
        $ip = urlencode($id);
        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=whitelist&ip=' . $ip . '" 
                title="' . $this->trans('Whitelist this IP', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-sjsuccess">
        <i class="material-icons">check_circle</i></a>';
    }

    public function displayUnwhitelistLink($token, $id, $name = null)
    {
        $ip = urlencode($id);
        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=unwhitelist&ip=' . $ip . '" 
                title="' . $this->trans('Remove from whitelist', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-sjwarning">
        <i class="material-icons">block</i></a>';
    }

    public function displayForceBlockLink($token, $id, $name = null)
    {
        $ip = urlencode($id);
        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=forceBlock&ip=' . $ip . '" 
                title="' . $this->trans('Force block', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-dark">
        <i class="material-icons">gavel</i></a>';
    }

    public function displayUnblockLink($token, $id, $name = null)
    {
        $ip = urlencode($id);
        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=unblockIp&ip=' . $ip . '" 
                title="' . $this->trans('Unblock IP', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-sjsecondary">
        <i class="material-icons">lock_open</i></a>';
    }

    public function displayViewLogsLink($token, $id, $name = null)
    {
        $ip = urlencode($id);
        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&viewlogs=1&ip=' . $ip . '" 
                title="' . $this->trans('View logs', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-sjinfo">
        <i class="material-icons">visibility</i></a>';
    }

    protected function renderLogsView($ip)
    {
        $this->meta_title = $this->trans('Logs for IP: %ip%', ['%ip%' => $ip], 'Modules.Sj4webfirewall.Admin');

        $filepath = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/ip_scores.json';
        $logs = [];

        if (file_exists($filepath)) {
            $json = file_get_contents($filepath);
            $data = json_decode($json, true);

            if (isset($data[$ip]['log']) && is_array($data[$ip]['log'])) {
                $logs = $data[$ip]['log'];
            }
        }

        $this->context->smarty->assign([
            'ip' => $ip,
            'logs' => $logs,
            'back_link' => $this->context->link->getAdminLink('AdminSj4webFirewallLog'),
        ]);

        $this->setTemplate('logs_view.tpl');
    }

}
